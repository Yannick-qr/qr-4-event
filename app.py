from fastapi import FastAPI, Depends, HTTPException, Form, Request, Body, UploadFile, File, status, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse, StreamingResponse
from sqlalchemy.orm import Session
from database import Base, engine, get_db, AdminUser, Event, EventRegistration, Participant, AdminLog
from passlib.hash import bcrypt
from datetime import timedelta
from database import utcnow
from supabase import create_client, Client
from utils import check_token_valid
import uuid
import os
import smtplib
import io
import qrcode
from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from typing import Optional, List
import httpx
import requests  # gardé pour /paypal/test-auth (sync) si tu veux
import json
import csv
import html
import re
import traceback
app = FastAPI()
load_dotenv()

# ========================
# CONFIG
# ========================
SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_ME_SECRET")
ALGORITHM = os.getenv("ALGORITHM", "HS256")

SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")

BASE_PUBLIC_URL = os.getenv("BASE_PUBLIC_URL", "http://127.0.0.1:8000")

PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID")
PAYPAL_SECRET = os.getenv("PAYPAL_SECRET")
PAYPAL_WEBHOOK_ID = os.getenv("PAYPAL_WEBHOOK_ID")
PAYPAL_API_BASE = os.getenv("PAYPAL_API_BASE", "https://api-m.paypal.com")

# ========================
# PARAMÈTRES LICENCE
# ========================
LICENSE_INCLUDED_CREDITS = int(os.getenv("LICENSE_INCLUDED_CREDITS", 50))
LICENSE_PRICE = float(os.getenv("LICENSE_PRICE", 149))

# ========================
# PARAMÈTRES PACKS CRÉDITS
# ========================
CREDIT_PACKS = {
    "small": {
        "credits": int(os.getenv("PARTICIPANT_PACK_SMALL", 50)),
        "price": float(os.getenv("PARTICIPANT_PACK_SMALL_PRICE", 49))
    },
    "medium": {
        "credits": int(os.getenv("PARTICIPANT_PACK_MEDIUM", 100)),
        "price": float(os.getenv("PARTICIPANT_PACK_MEDIUM_PRICE", 79))
    },
    "large": {
        "credits": int(os.getenv("PARTICIPANT_PACK_LARGE", 250)),
        "price": float(os.getenv("PARTICIPANT_PACK_LARGE_PRICE", 149))
    },
    "xl": {
        "credits": int(os.getenv("PARTICIPANT_PACK_XL", 500)),
        "price": float(os.getenv("PARTICIPANT_PACK_XL_PRICE", 249))
    },
    "enterprise": {
        "credits": int(os.getenv("PARTICIPANT_PACK_ENTERPRISE", 1000)),
        "price": float(os.getenv("PARTICIPANT_PACK_ENTERPRISE_PRICE", 399))
    }
}

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SUPABASE_BUCKET = os.getenv("SUPABASE_BUCKET", "event-images")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ========================
# APP INIT
# ========================


Base.metadata.create_all(bind=engine)
app.mount("/static", StaticFiles(directory="static"), name="static")

env = Environment(loader=FileSystemLoader("templates"))

# ========================
# ROUTE ACCUEIL (Landing Page)
# ========================

@app.get("/")
def landing_page():
    return FileResponse("static/landing_page.html")

# ========================
# ROUTE : Récupérer le client_id PayPal
# ========================
@app.get("/api/paypal-client-id")
def get_paypal_client_id(event_id: int = None, db: Session = Depends(get_db)):
    """
    Retourne le bon client_id PayPal :
    - Si event_id fourni et l’admin a configuré PayPal → renvoyer son client_id
    - Sinon fallback sur le global
    """
    client_id = PAYPAL_CLIENT_ID

    if event_id:
        event = db.query(Event).filter(Event.id == event_id).first()
        if event:
            admin = db.query(AdminUser).filter(AdminUser.id == event.created_by).first()
            if admin and admin.paypal_client_id:
                client_id = admin.paypal_client_id

    if not client_id:
        return JSONResponse(
            {"message": "Aucun client_id PayPal disponible"},
            status_code=500
        )
    return JSONResponse({"client_id": client_id})

# ========================
# ROUTE : Récupérer la config licence + crédits
# ========================
@app.get("/api/config")
def get_config():
    return {
        "success": True,
        "license": {
            "price": LICENSE_PRICE,
            "included_credits": LICENSE_INCLUDED_CREDITS
        },
        "packs": CREDIT_PACKS
    }


# ========================
# UTILS
# ========================

def send_confirmation_email(recipient_email, subject, participant, event, qr_data):
    """
    Envoie un email designé avec image de l'événement + QR code en PJ
    """
    try:
        msg = MIMEMultipart("mixed")
        msg["From"] = SMTP_USER
        msg["To"] = recipient_email
        msg["Subject"] = subject

        # Corps HTML
        body = f"""
<html lang="fr">
<head><meta charset="UTF-8"><title>Inscription confirmée</title></head>
<body style="font-family: Arial, sans-serif; background:#f5f6fa; padding:20px; margin:0;">
  <table align="center" width="100%" style="max-width:600px; background:#ffffff; border-radius:8px; box-shadow:0 2px 5px rgba(0,0,0,0.1);">

    <!-- Image de l’événement -->
    {"<tr><td><img src='" + (event.image_url or "") + "' alt='Image de l’événement' style='width:100%; border-radius:8px 8px 0 0;'></td></tr>" if getattr(event, "image_url", None) else ""}

    <tr>
      <td style="padding:25px; text-align:center;">
        <h2 style="color:#007bff;">🎉 Inscription confirmée</h2>
        <p style="font-size:16px; color:#333;">
          Merci <b>{html.escape(participant.name or '')}</b>, ton paiement de <b>{float(participant.amount):.2f} €</b> 
          pour <b>{html.escape(event.title or '')}</b> a bien été enregistré ✅
        </p>
        <p style="font-size:15px; color:#555;">
          📅 <b>Date :</b> {html.escape(event.date or '')}<br>
          📍 <b>Lieu :</b> {html.escape(event.location or '')}
        </p>

        <p style="margin:30px 0; font-size:14px; color:#888;">
          Ton QR code est joint à ce mail en pièce jointe.<br>
          Garde-le précieusement, il sera demandé à l’entrée.
        </p>
      </td>
    </tr>

    <tr>
      <td style="background:#f5f6fa; padding:15px; text-align:center; font-size:12px; color:#777;">
        © 2025 QR Event – Merci de ta confiance 🚀
      </td>
    </tr>
  </table>
</body>
</html>
        """
        msg.attach(MIMEText(body, "html"))

        # ✅ Génération du QR code en mémoire
        qr = qrcode.make(qr_data)
        img_bytes = io.BytesIO()
        qr.save(img_bytes, format="PNG")
        img_bytes.seek(0)

        part = MIMEBase("application", "octet-stream")
        part.set_payload(img_bytes.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", 'attachment; filename="qrcode.png"')
        msg.attach(part)

        # Envoi SMTP
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, recipient_email, msg.as_string())
        server.quit()

        return True
    except Exception as e:
        print("❌ Erreur envoi mail confirmation :", e)
        return False


def send_admin_email(recipient_email, subject, body_html):
    """
    Envoi d'un email HTML + plain/text (fallback) pour admin (sans QR code)
    """
    try:
        # ✅ Création du message multipart (plain + HTML)
        msg = MIMEMultipart("alternative")
        msg["From"] = SMTP_USER
        msg["To"] = recipient_email
        msg["Subject"] = subject

        # Version texte brut (fallback)
        body_text = "Bonjour,\n\nTon compte QR Event a bien été créé.\n\nConnecte-toi pour définir ton mot de passe."

        # Attacher la version texte + version HTML
        msg.attach(MIMEText(body_text, "plain", "utf-8"))
        msg.attach(MIMEText(body_html, "html", "utf-8"))

        # ✅ Envoi SMTP
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, recipient_email, msg.as_string())
        server.quit()

        return True
    except Exception as e:
        print("❌ Erreur envoi mail admin:", e)
        traceback.print_exc()
        return False


def check_token_valid(user: AdminUser, db: Session):
    if not user or not user.token:
        return False
    if not user.token_expiry or utcnow() > user.token_expiry:
        user.token = None
        user.token_expiry = None
        db.commit()
        return False
    return True


def log_admin_action(db: Session, admin_id: int, action: str, details: str = None):
    new_log = AdminLog(admin_id=admin_id, action=action, details=details)
    db.add(new_log)
    db.commit()

def is_password_reused(user: AdminUser, new_password: str) -> bool:
    """
    True si new_password correspond déjà au mot de passe courant de l'utilisateur.
    """
    try:
        if not user or not getattr(user, "password_hash", ""):
            return False
        return bcrypt.verify(new_password, user.password_hash)
    except Exception:
        return False




def get_current_user(token: str, db: Session):
    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not user:
        return None
    if not user.is_active:
        return None
    return user

# ========================
# ENDPOINT PROFIL
# ========================
@app.post("/api/me")
def get_profile(token: str = Form(...), db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    if not user:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})

    return {
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email": user.email,
        "avatar_url": getattr(user, "avatar_url", None)
    }


# ========================
# LOGIN
# ========================
@app.post("/login")
def login(email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(AdminUser).filter(AdminUser.email == email).first()

    if not user:
        return {"success": False, "message": "Utilisateur introuvable"}

    if not bcrypt.verify(password, user.password_hash):
        return {"success": False, "message": "Mot de passe incorrect"}

    if not user.is_active:
        return {"success": False, "message": "⚠️ Compte inactif, vérifie ton email"}

    # Génère un nouveau token valable 24h
    token = str(uuid.uuid4())
    expiry = utcnow() + timedelta(hours=24)
    user.token = token
    user.token_expiry = expiry
    db.commit()

    return {"success": True, "token": token, "email": user.email}

# ========================
# CHECK EMAIL (validation avant paiement)
# ========================
@app.post("/check-email")
def check_email(email: str = Form(...), db: Session = Depends(get_db)):
    existing = db.query(AdminUser).filter(AdminUser.email == email).first()
    if existing:
        raise HTTPException(status_code=400, detail="⚠️ Cet email est déjà utilisé.")
    return {"success": True}

# ========================
# REGISTER + PAIEMENT
# ========================
@app.post("/register")
def register(
    firstName: str = Form(""),
    lastName: str = Form(""),
    email: str = Form(...),
    db: Session = Depends(get_db)
):
    # 🧹 Nettoyage des entrées
    firstName = html.escape(firstName.strip())
    lastName = html.escape(lastName.strip())
    email = email.strip().lower()

    # Regex email basique
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return {"success": False, "message": "❌ Adresse email invalide."}

    # Vérifie si email existe déjà
    existing_user = db.query(AdminUser).filter(AdminUser.email == email).first()
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="⚠️ Cette adresse email est déjà associée à un compte existant."
        )

    # ✅ Crée un nouveau compte admin
    validation_token = str(uuid.uuid4())
    expiry = utcnow() + timedelta(hours=48)

    new_user = AdminUser(
        email=email,
        password_hash="",  # vide tant qu’il n’a pas défini son mdp
        is_active=False,
        token=validation_token,
        token_expiry=expiry,
        participant_credits=LICENSE_INCLUDED_CREDITS
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # ✅ Prépare le lien de validation
    verify_link = f"{BASE_PUBLIC_URL}/static/set-password.html?token={validation_token}"

    # ✅ Corps HTML de l’email admin
    body = f"""
    <html lang="fr">
    <head><meta charset="UTF-8"><title>Bienvenue sur QR Event</title></head>
    <body style="font-family: Arial, sans-serif; background:#f5f6fa; padding:20px; margin:0;">
      <table align="center" width="100%" style="max-width:600px; background:#ffffff; border-radius:8px; box-shadow:0 2px 5px rgba(0,0,0,0.1);">
        <tr>
          <td style="padding:25px; text-align:center;">
            <h2 style="color:#007bff;">🎉 {firstName}, bienvenue sur QR Event</h2>
            <p style="font-size:16px; color:#333;">
              Ton paiement est confirmé ✅
            </p>
            <p style="font-size:15px; color:#555;">
              Voici ton lien pour définir ton mot de passe (valable <b>48h</b>) :
            </p>
            <p style="margin:30px 0;">
              <a href="{verify_link}" style="background:#007bff; color:#ffffff; padding:12px 24px; text-decoration:none; border-radius:6px; font-weight:bold;">
                🔑 Définir mon mot de passe
              </a>
            </p>
            <p style="font-size:13px; color:#888;">Si le bouton ne fonctionne pas, copie-colle ce lien dans ton navigateur :<br>{verify_link}</p>
          </td>
        </tr>
      </table>
    </body>
    </html>
    """

    try:
        ok = send_admin_email(email, "Définir ton mot de passe - QR Event", body)
        if not ok:
            print(f"⚠️ Envoi d’email échoué pour {email} (send_admin_email=False)")
            return {
                "success": True,
                "message": "Compte créé ✅ mais l’email n’a pas pu être envoyé. Contacte l’admin."
            }
        else:
            print(f"✅ Email d’activation envoyé à {email}")
    except Exception as e:
        print("❌ Exception lors de l’envoi du mail d’activation :", e)
        traceback.print_exc()
        return {
            "success": True,
            "message": "Compte créé ✅ mais erreur lors de l’envoi du mail. Contacte l’admin."
        }

    return {
        "success": True,
        "message": "Paiement confirmé ✅, email envoyé avec lien pour définir le mot de passe."
    }


# ========================
# SET PASSWORD
# ========================
@app.post("/set-password")
def set_password(token: str = Form(...), new_password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not user:
        return {"success": False, "message": "Lien invalide."}

    now = utcnow()

    # Déjà activé / déjà un mot de passe -> used
    if user.is_active or (user.password_hash and user.password_hash.strip() != ""):
        # on invalide au cas où
        user.token = None
        user.token_expiry = None
        db.commit()
        return {"success": False, "message": "Ce lien a déjà été utilisé."}

    # Expiré -> expired
    if (user.token_expiry is None) or (now >= user.token_expiry):
        user.token = None
        user.token_expiry = None
        db.commit()
        return {"success": False, "message": "Lien expiré. Demandez un nouveau lien d’activation."}

    # Empêche de réutiliser le même mot de passe (si jamais il existait déjà)
    if is_password_reused(user, new_password):
        return JSONResponse(
            status_code=409,
            content={"success": False, "error": "Mot de passe déjà utilisé. Choisissez-en un différent."}
        )

    # Règle simple de complexité
    pwd = new_password.strip()
    if len(pwd) < 8 or \
       not re.search(r"[A-Z]", pwd) or \
       not re.search(r"[a-z]", pwd) or \
       not re.search(r"[0-9]", pwd):
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": "Mot de passe trop faible (min. 8 car., 1 maj, 1 min, 1 chiffre)."}
        )

    # OK : on active le compte et on invalide le token
    user.password_hash = bcrypt.hash(new_password)
    user.is_active = True
    user.token = None
    user.token_expiry = None
    db.commit()

    return {"success": True, "message": "Mot de passe défini. Vous pouvez vous connecter."}


# ========================
# ACTIVATION RESEND
# ========================
@app.post("/activation/resend")
def resend_activation(email: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(AdminUser).filter(AdminUser.email == email.strip().lower()).first()
    # Réponse générique pour éviter l’énumération d’emails
    generic = {"success": True, "message": "Si un compte existe, un email a été envoyé."}

    if not user:
        return generic

    if user.is_active:
        # Si déjà actif, inutile d’envoyer un lien d’activation
        return generic

    # Regénère un token 48h
    validation_token = str(uuid.uuid4())
    expiry = utcnow() + timedelta(hours=48)
    user.token = validation_token
    user.token_expiry = expiry
    db.commit()

    verify_link = f"{BASE_PUBLIC_URL}/static/set-password.html?token={validation_token}"

    body = f"""
    <html><head><meta charset="UTF-8"></head><body>
      <p>Voici ton lien pour définir ton mot de passe (valable <b>48h</b>) :</p>
      <p><a href="{verify_link}">🔑 Définir mon mot de passe</a></p>
      <p style="word-break:break-all;">{verify_link}</p>
    </body></html>
    """

    try:
        send_admin_email(user.email, "Nouveau lien d’activation - QR Event", body)
    except Exception:
        pass

    return generic


# ========================
# SET PASSWORD CHECK
# ========================
@app.get("/set-password/check")
def check_activation_token(token: str, db: Session = Depends(get_db)):
    # 1) token manquant -> invalid
    if not token or token.strip() == "":
        return {"valid": False, "reason": "invalid"}

    user = db.query(AdminUser).filter(AdminUser.token == token).first()

    # 2) token inconnu -> invalid (ne surtout pas dire "used")
    if not user:
        return {"valid": False, "reason": "invalid"}

    now = utcnow()

    # 3) déjà activé OU déjà un mot de passe -> used
    already_has_pwd = bool(user.password_hash and user.password_hash.strip() != "")
    if user.is_active or already_has_pwd:
        return {"valid": False, "reason": "used"}

    # 4) pas encore activé, mais token expiré -> expired
    if (user.token_expiry is None) or (now >= user.token_expiry):
        return {"valid": False, "reason": "expired"}

    # 5) OK
    return {"valid": True}


# ========================
# ACTIVATION CONFIRM
# ========================
@app.post("/activation/confirm")
def activation_confirm(token: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not user:
        return JSONResponse(status_code=404, content={"success": False, "error": "invalid", "message": "Lien invalide."})

    if not user.token_expiry or utcnow() >= user.token_expiry:
        user.token = None
        user.token_expiry = None
        db.commit()
        return JSONResponse(status_code=status.HTTP_410_GONE, content={"success": False, "error": "expired", "message": "Lien expiré."})

    # ✅ Si mdp déjà défini mais compte pas encore actif → on active
    if (user.password_hash and user.password_hash.strip() != "") and not user.is_active:
        user.is_active = True
        user.token = None
        user.token_expiry = None
        db.commit()
        return {"success": True, "message": "Compte activé. Vous pouvez vous connecter."}

    # Déjà actif
    if user.is_active:
        return {"success": True, "message": "Compte déjà actif."}

    # Sinon, il n’a pas encore posé de mot de passe → passer par /set-password
    return JSONResponse(status_code=400, content={"success": False, "error": "need_password", "message": "Veuillez d'abord définir un mot de passe."})


# ========================
# TEST
# ========================
@app.get("/_debug/activation")
def debug_activation(token: str, db: Session = Depends(get_db)):
    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not user:
        return {"found": False}

    return {
        "found": True,
        "user_id": user.id,
        "email": user.email,
        "is_active": user.is_active,
        "has_password_hash": bool(user.password_hash and user.password_hash.strip() != ""),
        "token_equals": (user.token == token),
        "token_db": user.token,
        "token_expiry_utc": user.token_expiry.isoformat() if user.token_expiry else None,
    }


# ========================
# BUY EVENT CREDITS (ajout après paiement validé)
# ========================
@app.post("/buy-credits")
def buy_credits(token: str = Form(...), quantity: int = Form(...), db: Session = Depends(get_db)):
    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not check_token_valid(user, db):
        return {"success": False, "message": "Session invalide"}

    try:
        quantity = int(quantity)
    except (TypeError, ValueError):
        return {"success": False, "message": "Quantité de crédits invalide"}

    if quantity <= 0:
        return {"success": False, "message": "Quantité de crédits invalide"}

    user.participant_credits += quantity
    db.commit()

    return {"success": True, "new_balance": user.participant_credits}


# ========================
# CRÉER UNE COMMANDE PAYPAL (licence + packs de crédits)
# ========================
@app.post("/paypal/create-order")
async def create_order(request: Request):
    try:
        data = await request.json()
        print("📥 Données reçues du frontend:", data)

        order_type = data.get("type", "credits")  # "license" ou "credits"

        # 💰 Définir les prix côté backend (depuis .env)
        if order_type == "license":
            amount = LICENSE_PRICE

        elif order_type == "credits":
            credits = int(data.get("credits", 1))

            # 🔍 Trouver le pack correspondant dans CREDIT_PACKS
            matched_pack = None
            for pack in CREDIT_PACKS.values():
                if pack["credits"] == credits:
                    matched_pack = pack
                    break

            if not matched_pack:
                return {"success": False, "message": f"Pack de crédits invalide: {credits}"}

            amount = matched_pack["price"]

        else:
            return {"success": False, "message": "❌ Type d'achat invalide"}

        # 🔹 Étape 1 : Authentification OAuth PayPal (httpx)
        async with httpx.AsyncClient() as client:
            auth_req = await client.post(
                f"{PAYPAL_API_BASE}/v1/oauth2/token",
                headers={"Accept": "application/json", "Accept-Language": "en_US"},
                data={"grant_type": "client_credentials"},
                auth=(PAYPAL_CLIENT_ID, PAYPAL_SECRET),
                timeout=30
            )

        if auth_req.status_code != 200:
            return {"success": False, "message": "OAuth failed", "paypal_response": auth_req.text}

        access_token = auth_req.json().get("access_token")
        if not access_token:
            return {"success": False, "message": "Pas de access_token", "paypal_response": auth_req.json()}

        # 🔹 Étape 2 : Créer la commande PayPal
        async with httpx.AsyncClient() as client:
            order_req = await client.post(
                f"{PAYPAL_API_BASE}/v2/checkout/orders",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {access_token}"
                },
                json={
                    "intent": "CAPTURE",
                    "purchase_units": [{
                        "amount": {
                            "currency_code": "EUR",
                            "value": str(amount)
                        }
                    }]
                },
                timeout=30
            )

        order_data = order_req.json()

        if "id" not in order_data:
            return {"success": False, "message": "PayPal n’a pas renvoyé d’ID", "paypal_response": order_data}

        return {"success": True, "id": order_data["id"], "paypal_response": order_data}

    except Exception as e:
        print("❌ Exception dans create_order:", e)
        traceback.print_exc()
        return {"success": False, "message": str(e)}


# ========================
# TEST AUTH PAYPAL
# ========================
@app.get("/paypal/test-auth")
def test_auth():
    auth_req = requests.post(
        f"{PAYPAL_API_BASE}/v1/oauth2/token",
        headers={"Accept": "application/json", "Accept-Language": "en_US"},
        data={"grant_type": "client_credentials"},
        auth=(PAYPAL_CLIENT_ID, PAYPAL_SECRET)
    )
    return {
        "status_code": auth_req.status_code,
        "response": auth_req.text
    }

# ========================
# AJOUTER DES CRÉDITS (via PayPal Dashboard)
# ========================
@app.post("/admin/credits/add")
def add_credits(payload: dict = Body(...), db: Session = Depends(get_db)):
    token = payload.get("token")
    credits = payload.get("credits", 0)
    payment_id = payload.get("payment_id")

    # Vérifier le token
    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not check_token_valid(user, db):
        return {"success": False, "message": "Non autorisé"}

    # Vérifier le format des crédits
    try:
        credits = int(credits)
    except (TypeError, ValueError):
        return {"success": False, "message": "Crédits invalides"}
    if credits <= 0:
        return {"success": False, "message": "Crédits invalides"}

    # Ajouter les crédits
    user.participant_credits += credits
    db.commit()

    # Log l'action pour le suivi (optionnel mais recommandé)
    log_admin_action(db, user.id, "ADD_CREDITS", f"+{credits} crédits ajoutés (payment_id={payment_id})")

    return {
        "success": True,
        "new_credits": user.participant_credits
    }

# ========================
# REGISTER PARTICIPANT (après paiement réussi)
# ========================
@app.post("/register_participant")
def register_participant(
    background_tasks: BackgroundTasks,
    first_name: str = Form(...),
    last_name: str = Form(...),
    email: str = Form(...),
    event_id: int = Form(...),
    amount: float = Form(...),
    transaction_id: str = Form(...),
    db: Session = Depends(get_db)
):
    try:
        # 🔒 Nettoyage des entrées
        safe_first = html.escape(re.sub(r"[<>]", "", first_name.strip()))
        safe_last = html.escape(re.sub(r"[<>]", "", last_name.strip()))
        safe_name = f"{safe_first} {safe_last}".strip() or "Participant"
        safe_email = html.escape(email.strip().lower())

        # Vérif email format
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", safe_email):
            return {"success": False, "message": "❌ Email invalide."}

        # Vérif event
        event = db.query(Event).filter(Event.id == event_id, Event.is_active == True).first()
        if not event:
            return {"success": False, "message": "❌ Événement introuvable ou inactif."}

        # Vérifie quota participants
        participants_count = db.query(Participant).filter(Participant.event_id == event.id).count()
        if event.max_participants and participants_count >= event.max_participants:
            return {"success": False, "message": "⚠️ Événement complet."}

        # Vérifie doublon transaction
        if db.query(Participant).filter(Participant.transaction_id == transaction_id).first():
            return {"success": True, "message": "ℹ️ Déjà enregistré."}

        # Vérifie crédits admin
        admin = db.query(AdminUser).filter(AdminUser.id == event.created_by).first()
        if not admin:
            return {"success": False, "message": "⚠️ Admin introuvable."}
        if admin.participant_credits <= 0:
            return {"success": False, "message": "⚠️ Pas assez de crédits participants."}

        # ✅ Crée le participant (QR code aléatoire si colonne présente)
        qr_code_value = str(uuid.uuid4())
        participant_kwargs = {
            "name": safe_name,
            "email": safe_email,
            "event_id": event_id,
            "amount": float(amount) if amount else event.price,
            "transaction_id": transaction_id,
            "created_at": utcnow()
        }
        # compat: n'ajoute qr_code que si l'ORM a la colonne
        if hasattr(Participant, "qr_code"):
            participant_kwargs["qr_code"] = qr_code_value

        participant = Participant(**participant_kwargs)
        db.add(participant)

        # Décrémente crédits
        admin.participant_credits -= 1
        db.commit()
        db.refresh(participant)

        # ✅ Génère le QR data (prend qr_code si dispo, sinon id)
        qr_token = getattr(participant, "qr_code", None) or str(participant.id)
        qr_data = f"{BASE_PUBLIC_URL}/api/event/{event_id}?participant={qr_token}"

        # Envoi email de confirmation (background)
        background_tasks.add_task(
            send_confirmation_email,
            recipient_email=safe_email,
            subject=f"Confirmation inscription - {event.title}",
            participant=participant,
            event=event,
            qr_data=qr_data
        )

        return {"success": True, "message": "🎉 Inscription enregistrée avec succès, email envoyé."}

    except Exception as e:
        print("❌ Exception dans /register_participant:", e)
        traceback.print_exc()
        return {"success": False, "message": f"❌ Erreur serveur : {str(e)}"}


# ========================
# USER INFO (profil connecté)
# ========================
@app.post("/me")
def get_me(token: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(AdminUser).filter(AdminUser.token == token).first()

    if not check_token_valid(user, db):
        return {"success": False, "message": "Session invalide"}

    # Construit un nom lisible
    if hasattr(user, "first_name") and hasattr(user, "last_name"):
        name = f"{user.first_name or ''} {user.last_name or ''}".strip()
    elif hasattr(user, "name"):
        name = user.name
    else:
        # fallback : utiliser la partie avant @ de l'email
        name = user.email.split("@")[0]

    return {
        "success": True,
        "email": user.email,
        "name": name,
        "credits": user.participant_credits
    }

# ========================
# PAYPAL ADMIN (config perso)
# ========================

@app.post("/admin/paypal/set")
def set_paypal_credentials(
    client_id: str = Form(...),
    secret: str = Form(...),
    token: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not check_token_valid(user, db):
        return {"success": False, "message": "Non autorisé"}

    user.paypal_client_id = client_id
    user.paypal_secret = secret
    db.commit()

    log_admin_action(db, user.id, "SET_PAYPAL", f"Admin {user.email} a configuré un compte PayPal")

    return {"success": True, "message": "Compte PayPal enregistré avec succès"}


@app.post("/admin/paypal/status")
def get_paypal_status(token: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not check_token_valid(user, db):
        return {"success": False, "message": "Non autorisé"}

    return {
        "success": True,
        "configured": bool(user.paypal_client_id and user.paypal_secret),
        "client_id": user.paypal_client_id if user.paypal_client_id else None
    }


@app.post("/admin/paypal/delete")
def delete_paypal_account(
    token: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not check_token_valid(user, db):
        return {"success": False, "message": "Non autorisé"}

    if not bcrypt.verify(password, user.password_hash):
        return {"success": False, "message": "Mot de passe incorrect"}

    user.paypal_client_id = None
    user.paypal_secret = None
    db.commit()

    log_admin_action(db, user.id, "DELETE_PAYPAL", f"Admin {user.email} a supprimé son compte PayPal")

    return {"success": True, "message": "Compte PayPal supprimé avec succès"}


# ========================
# EVENTS
# ========================
ALLOWED_IMAGE_CT = {"image/png", "image/jpeg", "image/jpg", "image/webp"}
MAX_IMAGE_BYTES = 5 * 1024 * 1024  # 5MB

def _validate_image_upload(image: UploadFile, file_content: bytes):
    if image.content_type not in ALLOWED_IMAGE_CT:
        raise HTTPException(status_code=400, detail="Type d'image non autorisé.")
    if len(file_content) > MAX_IMAGE_BYTES:
        raise HTTPException(status_code=400, detail="Image trop lourde (max 5MB).")

@app.post("/admin/events")
async def create_event(
    token: str = Form(...),
    title: str = Form(...),
    description: str = Form(""),
    date: str = Form(...),
    location: str = Form(...),
    price: float = Form(...),
    max_participants: int = Form(100),
    checkin_login: str = Form(""),
    checkin_password: str = Form(""),
    image: UploadFile = File(None),
    db: Session = Depends(get_db)
):
    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not check_token_valid(user, db):
        return {"success": False, "message": "Non autorisé"}

    image_url = None
    if image:
        file_content = await image.read()
        _validate_image_upload(image, file_content)

        filename = f"{uuid.uuid4()}_{re.sub(r'[^A-Za-z0-9._-]', '_', image.filename)}"

        try:
            res = supabase.storage.from_(SUPABASE_BUCKET).upload(
                filename, file_content, {"content-type": image.content_type}
            )
            if res:  # ✅ si pas d’exception → upload OK
                image_url = supabase.storage.from_(SUPABASE_BUCKET).get_public_url(filename)
        except Exception as e:
            return {"success": False, "message": f"❌ Erreur upload image Supabase: {str(e)}"}

    new_event = Event(
        title=title,
        description=description,
        date=date,
        location=location,
        price=price,
        created_by=user.id,
        checkin_login=checkin_login,
        checkin_password=checkin_password,
        max_participants=max_participants,
        image_url=image_url
    )
    db.add(new_event)
    db.commit()
    db.refresh(new_event)

    return {
        "success": True,
        "message": "✅ Événement créé avec succès",
        "event_id": new_event.id,
        "image_url": image_url
    }


@app.post("/admin/events/update")
async def update_event(
    event_id: int = Form(...),
    title: str = Form(...),
    description: str = Form(""),
    date: str = Form(...),
    location: str = Form(...),
    price: float = Form(...),
    checkin_login: str = Form(None),
    checkin_password: str = Form(None),
    max_participants: int = Form(100),
    token: str = Form(...),
    image: UploadFile = File(None),   # ✅ nouveau
    db: Session = Depends(get_db)
):

    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not check_token_valid(user, db):
        return {"success": False, "message": "Non autorisé"}

    event = db.query(Event).filter(Event.id == event_id, Event.created_by == user.id).first()
    if not event:
        return {"success": False, "message": "❌ Événement introuvable"}

    event.title = title
    event.description = description
    event.date = date
    event.location = location
    event.price = price
    event.max_participants = max_participants
    if checkin_login is not None:
        event.checkin_login = checkin_login
    if checkin_password is not None:
        event.checkin_password = checkin_password

    # ✅ Met à jour l'image si uploadée
    if image:
        file_content = await image.read()
        _validate_image_upload(image, file_content)

        filename = f"{uuid.uuid4()}_{re.sub(r'[^A-Za-z0-9._-]', '_', image.filename)}"
        try:
            res = supabase.storage.from_(SUPABASE_BUCKET).upload(
                filename, file_content, {"content-type": image.content_type}
            )
            if res:
                event.image_url = supabase.storage.from_(SUPABASE_BUCKET).get_public_url(filename)
        except Exception as e:
            return {"success": False, "message": f"❌ Erreur upload image Supabase: {str(e)}"}

    db.commit()
    db.refresh(event)

    return {
        "success": True,
        "message": "✅ Événement mis à jour avec succès",
        "event_id": event.id,
        "image_url": event.image_url
    }


@app.post("/admin/events/delete")
def delete_event(
    event_id: int = Form(...),
    token: str = Form(...),
    db: Session = Depends(get_db)
):

    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not check_token_valid(user, db):
        return {"success": False, "message": "Non autorisé"}

    event = db.query(Event).filter(Event.id == event_id, Event.created_by == user.id).first()
    if not event:
        return {"success": False, "message": "❌ Événement introuvable"}

    db.delete(event)
    db.commit()
    return {
        "success": True,
        "message": "🗑️ Événement supprimé avec succès",
        "event_id": event_id
    }


@app.post("/admin/events/toggle")
def toggle_event(
    event_id: int = Form(...),
    token: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not check_token_valid(user, db):
        return {"success": False, "message": "Non autorisé"}

    event = db.query(Event).filter(Event.id == event_id, Event.created_by == user.id).first()
    if not event:
        return {"success": False, "message": "❌ Événement introuvable"}

    # ✅ on inverse l’état actif/inactif
    event.is_active = not event.is_active
    db.commit()

    return {
        "success": True,
        "message": f"{'✅ Événement activé' if event.is_active else '⏸️ Événement désactivé'}",
        "event_id": event.id,
        "is_active": event.is_active
    }


@app.get("/event/{event_id}", response_class=HTMLResponse)
def public_event(event_id: int, db: Session = Depends(get_db)):
    event = db.query(Event).filter(Event.id == event_id, Event.is_active == True).first()
    if not event:
        return HTMLResponse("<h2>Événement introuvable ou inactif ❌</h2>", status_code=404)

    # 🔒 échappes pour éviter XSS
    title = html.escape(event.title or "")
    desc = html.escape(event.description or "")
    loc = html.escape(event.location or "")
    date = html.escape(event.date or "")
    price = html.escape(str(event.price) if event.price is not None else "")

    image_block = ""
    if getattr(event, "image_url", None):
        img_src = html.escape(event.image_url)
        image_block = f'<div style="margin:20px 0;"><img src="{img_src}" alt="Affiche" style="max-width:400px; border-radius:8px;"></div>'

    return f"""
    <html>
    <head>
        <title>{title} - QR Event</title>
    </head>
    <body style="font-family: Arial, sans-serif; background: #f5f6fa; padding:20px;">
        <h1>{title}</h1>
        {image_block}
        <p><b>Description :</b> {desc}</p>
        <p><b>Date :</b> {date}</p>
        <p><b>Lieu :</b> {loc}</p>
        <p><b>Prix :</b> {price} €</p>
        <hr>
        <button style="padding:10px 20px; background:#007bff; color:white; border:none; border-radius:5px;">
            S'inscrire / Payer
        </button>
    </body>
    </html>
    """

# ========================
# API PUBLIC EVENT (JSON)
# ========================
@app.get("/api/event/{event_id}")
@app.get("/api/events/{event_id}")      # ← alias facultatif
def api_event(event_id: int, db: Session = Depends(get_db)):
    event = db.query(Event).filter(Event.id == event_id, Event.is_active == True).first()
    if not event:
        raise HTTPException(status_code=404, detail="Not found")

    participants_count = db.query(Participant).filter(Participant.event_id == event.id).count()

    return {
        "success": True,
        "event": {
            "id": event.id,
            "title": event.title,
            "description": event.description,
            "date": event.date,
            "location": event.location,
            "price": event.price,
            "is_active": event.is_active,
            "max_participants": event.max_participants,
            "participants_count": participants_count,
            "public_url": f"{BASE_PUBLIC_URL}/static/event.html?id={event.id}",
            "image_url": event.image_url
        }
    }

# ========================
# EVENT PAYMENT (Public)
# ========================
@app.post("/event/{event_id}/pay")
async def event_pay(event_id: int, request: Request, db: Session = Depends(get_db)):
    """Créer une commande PayPal pour un participant à un événement"""
    try:
        # Vérifie que l'événement existe et est actif
        event = db.query(Event).filter(Event.id == event_id, Event.is_active == True).first()
        if not event:
            return {"id": None, "message": "❌ Événement introuvable ou inactif"}

        # Récupère l'admin créateur
        admin = db.query(AdminUser).filter(AdminUser.id == event.created_by).first()
        if not admin:
            return {"id": None, "message": "❌ Admin introuvable"}

        # ✅ Vérifie crédits disponibles avant même de créer la commande PayPal
        if admin.participant_credits <= 0:
            return {"id": None, "message": "⚠️ Pas assez de crédits participants"}

        # ✅ Vérifie quota participants (si max_participants défini)
        participants_count = db.query(Participant).filter(Participant.event_id == event.id).count()
        if event.max_participants and participants_count >= event.max_participants:
            return {"id": None, "message": "⚠️ Événement complet"}

        # Sélectionne les credentials PayPal
        client_id = admin.paypal_client_id if admin and admin.paypal_client_id else PAYPAL_CLIENT_ID
        secret = admin.paypal_secret if admin and admin.paypal_secret else PAYPAL_SECRET

        # 🔹 Authentification PayPal
        async with httpx.AsyncClient() as client:
            auth_req = await client.post(
                f"{PAYPAL_API_BASE}/v1/oauth2/token",
                headers={"Accept": "application/json", "Accept-Language": "en_US"},
                data={"grant_type": "client_credentials"},
                auth=(client_id, secret),
                timeout=30
            )
        if auth_req.status_code != 200:
            return {"id": None, "message": "❌ OAuth PayPal échoué", "paypal_response": auth_req.text}

        access_token = auth_req.json().get("access_token")
        if not access_token:
            return {"id": None, "message": "Pas de access_token", "paypal_response": auth_req.json()}

        # 🔹 Crée la commande PayPal (montant = prix de l’événement)
        async with httpx.AsyncClient() as client:
            order_req = await client.post(
                f"{PAYPAL_API_BASE}/v2/checkout/orders",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {access_token}"
                },
                json={
                    "intent": "CAPTURE",
                    "purchase_units": [{
                        "reference_id": str(event.id),  # utile dans webhook
                        "amount": {"currency_code": "EUR", "value": str(event.price)}
                    }]
                },
                timeout=30
            )

        order_data = order_req.json()
        if "id" not in order_data:
            return {"id": None, "message": "PayPal n’a pas renvoyé d’ID", "paypal_response": order_data}

        # ✅ Retour toujours au format attendu par PayPal SDK
        return {"id": order_data["id"]}

    except Exception as e:
        print("❌ Exception event_pay:", e)
        traceback.print_exc()
        return {"id": None, "message": str(e)}

    
# ========================
# LIST EVENTS
# ========================
@app.post("/admin/events/list")
def list_events(token: str = Form(...), db: Session = Depends(get_db)):
    # Vérifier utilisateur
    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not user or not check_token_valid(user, db):
        return {"success": False, "message": "Non autorisé"}

    # ⚡ Charger seulement ses événements
    events = db.query(Event).filter(Event.created_by == user.id).all()

    return {
        "success": True,
        "participant_credits": getattr(user, "participant_credits", 0),
        "email": user.email,   # 👈 pour debug
        "events": [
            {
                "id": e.id,
                "title": e.title,
                "description": e.description,
                "date": e.date,
                "location": e.location,
                "price": e.price,
                "is_active": e.is_active,
                "is_locked": e.is_locked,
                "max_participants": e.max_participants,
                "image_url": e.image_url,
                "public_url": f"{BASE_PUBLIC_URL}/static/event.html?id={e.id}",
                "checkin_login": e.checkin_login,
                "checkin_password": e.checkin_password,
            }
            for e in events
        ]
    }

# ========================
# ADMIN : RECHERCHE PARTICIPANTS
# ========================
@app.post("/admin/events/participants")
def admin_search_participants(
    token: str = Form(...),
    event_id: int = Form(...),
    q: Optional[str] = Form(""),
    db: Session = Depends(get_db)
):
    # 1) Auth admin
    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not check_token_valid(user, db):
        return {"success": False, "error": "Non autorisé"}

    # 2) Base query (sur l'événement demandé)
    qry = db.query(Participant).filter(Participant.event_id == event_id)

    # 3) Filtre texte : on cherche dans name OU email
    if q:
        like = f"%{q.strip()}%"
        qry = qry.filter(
            (Participant.name.ilike(like)) |
            (Participant.email.ilike(like))
        )

    # 4) Limite soft + tri (tri par nom complet)
    qry = qry.order_by(Participant.name.asc()).limit(50)
    rows: List[Participant] = qry.all()

    # 5) Mapping : découper 'name' -> first_name / last_name
    results = []
    for p in rows:
        full_name = p.name or ""
        parts = full_name.split()
        first_name = parts[0] if parts else ""
        last_name = " ".join(parts[1:]) if len(parts) > 1 else ""

        results.append({
            "id": p.id,
            "qr_code": getattr(p, "qr_code", None),
            "first_name": first_name,
            "last_name": last_name,
            "email": p.email,
            "amount_paid": getattr(p, "amount", None),   # aligne le nom attendu par le front
            "scanned": bool(getattr(p, "scanned", False))
        })

    return {"success": True, "participants": results}


# ========================
# ADMIN : INSCRIPTIONS PAYÉES
# ========================
@app.post("/admin/paid-registrations")
def get_paid_registrations(token: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not check_token_valid(user, db):
        return {"success": False, "message": "Non autorisé"}

    # 🔎 On filtre uniquement les événements créés par l’admin connecté
    events = db.query(Event).filter(Event.created_by == user.id).all()
    event_ids = [e.id for e in events]

    participants = db.query(Participant).filter(Participant.event_id.in_(event_ids)).all()

    result = []
    for p in participants:
        event = db.query(Event).filter_by(id=p.event_id).first()
        result.append({
            "nom": p.name.split(" ")[-1] if p.name else "",
            "prenom": p.name.split(" ")[0] if p.name else "",
            "email": p.email,
            "evenement": event.title if event else "",
            "montant": p.amount,
            "date": p.created_at.strftime("%Y-%m-%d %H:%M") if p.created_at else ""
        })

    return {"success": True, "registrations": result}


@app.post("/admin/paid-registrations/csv")
def export_paid_registrations_csv(token: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not check_token_valid(user, db):
        return {"success": False, "message": "Non autorisé"}

    events = db.query(Event).filter(Event.created_by == user.id).all()
    event_ids = [e.id for e in events]

    participants = db.query(Participant).filter(Participant.event_id.in_(event_ids)).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Nom", "Prénom", "Email", "Événement", "Montant (€)", "Date"])

    for p in participants:
        event = db.query(Event).filter_by(id=p.event_id).first()
        writer.writerow([
            p.name.split(" ")[-1] if p.name else "",
            p.name.split(" ")[0] if p.name else "",
            p.email,
            event.title if event else "",
            p.amount,
            p.created_at.strftime("%Y-%m-%d %H:%M") if p.created_at else ""
        ])

    output.seek(0)
    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=inscriptions_payees.csv"}
    )


# ========================
# CHECK-IN (Login)
# ========================
@app.post("/checkin/login")
def checkin_login(
    login: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    event = db.query(Event).filter(Event.checkin_login == login, Event.checkin_password == password).first()
    if not event:
        return {"success": False, "message": "Identifiants invalides"}

    return {
        "success": True,
        "event_id": event.id,
        "event_title": event.title
    }

# ========================
# CHECK-IN (Scan Event)
# ========================
@app.post("/checkin/scan")
def checkin_scan(
    event_id: int = Form(...),
    qr_code: str = Form(...),
    db: Session = Depends(get_db)
):
    try:
        print(f"📥 [SCAN] Reçu event_id={event_id}, qr_code={qr_code}")

        participant = None

        # 1) Chercher par qr_code si la colonne existe
        if hasattr(Participant, "qr_code"):
            print("🔎 Recherche par Participant.qr_code…")
            participant = db.query(Participant).filter(
                Participant.event_id == event_id,
                Participant.qr_code == qr_code
            ).first()

        # 2) Fallback par id uniquement si qr_code est bien un entier
        if not participant and qr_code.isdigit():
            print("🔎 Recherche par Participant.id (entier)…")
            participant = db.query(Participant).filter(
                Participant.event_id == event_id,
                Participant.id == int(qr_code)
            ).first()

        if not participant:
            print("⚠️ Aucun participant trouvé pour ce QR code.")
            return {"success": False, "message": "QR code invalide ou participant introuvable"}

        # Récupérer l’event
        event = db.query(Event).filter(Event.id == event_id).first()
        if not event:
            print(f"⚠️ Aucun event trouvé avec id={event_id}")

        # Construire réponse
        response = {
            "success": True,
            "participant": {
                "first_name": (participant.name.split(" ")[0] if participant.name else ""),
                "last_name": (" ".join(participant.name.split(" ")[1:]) if participant.name and " " in participant.name else ""),
                "email": getattr(participant, "email", ""),
                "amount_paid": getattr(participant, "amount", 0),
                "event_title": getattr(event, "title", ""),
                "date": getattr(event, "date", ""),
                "location": getattr(event, "location", ""),
                "scanned": getattr(participant, "scanned", False)
            }
        }

        print(f"✅ Scan réussi: {response}")
        return response

    except Exception as e:
        print("❌ Erreur checkin_scan:", repr(e))
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")

# ========================
# CHECK-IN (Validate)
# ========================
@app.post("/checkin/validate")
def checkin_validate(
    event_id: int = Form(...),
    qr_code: str = Form(...),
    db: Session = Depends(get_db)
):
    participant = None

    # 1) Essai par qr_code si la colonne existe
    if hasattr(Participant, "qr_code"):
        participant = db.query(Participant).filter(
            Participant.event_id == event_id,
            Participant.qr_code == qr_code
        ).first()

    # 2) Fallback par id uniquement si qr_code est bien un entier
    if not participant and qr_code.isdigit():
        participant = db.query(Participant).filter(
            Participant.event_id == event_id,
            Participant.id == int(qr_code)
        ).first()

    if not participant:
        return {"success": False, "message": "Participant introuvable"}

    if participant.scanned:
        return {
            "success": False,
            "message": f"⚠️ Déjà scanné à {participant.scanned_at}"
        }

    participant.scanned = True
    participant.scanned_at = utcnow()
    db.commit()

    return {
        "success": True,
        "message": f"✅ Check-in validé pour {participant.name}"
    }



# ========================
# WEBHOOK PAYPAL (CAPTURE ONLY)
# ========================
@app.post("/paypal/webhook")
async def paypal_webhook(request: Request, db: Session = Depends(get_db)):
    try:
        body = await request.body()
        event = json.loads(body)

        # 🔒 Vérification de la signature PayPal (en-têtes insensibles à la casse)
        hdr = {k.lower(): v for k, v in request.headers.items()}
        verify_url = f"{PAYPAL_API_BASE}/v1/notifications/verify-webhook-signature"
        payload = {
            "transmission_id": hdr.get("paypal-transmission-id"),
            "transmission_time": hdr.get("paypal-transmission-time"),
            "cert_url": hdr.get("paypal-cert-url"),
            "auth_algo": hdr.get("paypal-auth-algo"),
            "transmission_sig": hdr.get("paypal-transmission-sig"),
            "webhook_id": PAYPAL_WEBHOOK_ID,
            "webhook_event": event
        }

        async with httpx.AsyncClient() as client:
            r = await client.post(verify_url, auth=(PAYPAL_CLIENT_ID, PAYPAL_SECRET), json=payload, timeout=30)
        verification = r.json()
        print("🔎 Vérification PayPal:", verification)

        if verification.get("verification_status") != "SUCCESS":
            return JSONResponse(status_code=400, content={"success": False, "message": "Signature invalide"})

        # 📩 Lecture de l’événement
        event_type = event.get("event_type")
        resource = event.get("resource", {})
        print(f"📩 Webhook reçu: {event_type}")
        print(f"Payload: {json.dumps(event, indent=2)}")

        # 👉 On ne traite que les CAPTURES validées
        if event_type != "PAYMENT.CAPTURE.COMPLETED":
            return {"success": True, "message": f"Ignoré {event_type}"}

        # ---------------------------
        # EXTRACTION DES INFOS
        # ---------------------------
        amount = resource.get("amount", {}).get("value")
        transaction_id = resource.get("id")
        order_id = resource.get("supplementary_data", {}).get("related_ids", {}).get("order_id")

        if not order_id:
            return {"success": False, "message": "order_id manquant dans la capture"}

        # 🔹 Authentification PayPal
        async with httpx.AsyncClient() as client:
            auth_req = await client.post(
                f"{PAYPAL_API_BASE}/v1/oauth2/token",
                headers={"Accept": "application/json", "Accept-Language": "en_US"},
                data={"grant_type": "client_credentials"},
                auth=(PAYPAL_CLIENT_ID, PAYPAL_SECRET),
                timeout=30
            )
        if auth_req.status_code != 200:
            return {"success": False, "message": "OAuth PayPal échoué", "paypal_response": auth_req.text}

        access_token = auth_req.json().get("access_token")
        if not access_token:
            return {"success": False, "message": "Impossible d’obtenir access_token"}

        # 🔹 Récupérer l’Order complet
        async with httpx.AsyncClient() as client:
            order_req = await client.get(
                f"{PAYPAL_API_BASE}/v2/checkout/orders/{order_id}",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=30
            )
        order_data = order_req.json()
        print("🔎 Order récupéré:", json.dumps(order_data, indent=2))

        payer = order_data.get("payer", {})
        payer_email = payer.get("email_address")
        payer_name = payer.get("name", {}).get("given_name")

        try:
            event_id = int(order_data["purchase_units"][0]["reference_id"])
        except Exception:
            return {"success": False, "message": "event_id manquant dans l’order"}

        # ---------------------------
        # VÉRIFS DB
        # ---------------------------
        if db.query(EventRegistration).filter_by(payment_id=transaction_id).first():
            return {"success": True, "message": "Paiement déjà enregistré"}
        if db.query(Participant).filter_by(transaction_id=transaction_id).first():
            return {"success": True, "message": "Participant déjà enregistré"}

        event_db = db.query(Event).filter(Event.id == event_id).first()
        if not event_db:
            return {"success": False, "message": "Événement introuvable"}

        # ✅ Vérifie quota participants (sécurité)
        participants_count = db.query(Participant).filter(Participant.event_id == event_db.id).count()
        if event_db.max_participants and participants_count >= event_db.max_participants:
            return {"success": False, "message": "⚠️ Événement complet (après capture PayPal)"}

        # ✅ Vérifie crédits admin (sécurité)
        admin = db.query(AdminUser).filter(AdminUser.id == event_db.created_by).first()
        if not admin:
            return {"success": False, "message": "Admin introuvable"}
        if admin.participant_credits <= 0:
            return {"success": False, "message": "⚠️ Pas assez de crédits (après capture PayPal)"}

        # ---------------------------
        # CRÉATION EN DB
        # ---------------------------
        new_reg = EventRegistration(user_id=None, event_id=event_id, payment_id=transaction_id)
        db.add(new_reg)

        participant_kwargs = {
            "name": payer_name or (payer_email.split("@")[0] if payer_email else "Participant"),
            "email": payer_email,
            "amount": float(amount) if amount else event_db.price,
            "transaction_id": transaction_id,
            "event_id": event_id,
            "created_at": utcnow()
        }
        if hasattr(Participant, "qr_code"):
            participant_kwargs["qr_code"] = str(uuid.uuid4())

        participant = Participant(**participant_kwargs)
        db.add(participant)

        admin.participant_credits -= 1
        db.commit()
        db.refresh(participant)

        # ✅ Génère le QR data (qr_code si dispo, sinon id)
        qr_token = getattr(participant, "qr_code", None) or str(participant.id)
        qr_data = f"{BASE_PUBLIC_URL}/api/event/{event_id}?participant={qr_token}"

        # ✅ Envoi email confirmation
        try:
            send_confirmation_email(
                recipient_email=payer_email,
                subject=f"Confirmation inscription - {event_db.title}",
                participant=participant,
                event=event_db,
                qr_data=qr_data
            )
        except Exception as e:
            print("❌ Erreur envoi email participant webhook:", e)

        return {"success": True, "message": "Inscription validée et email envoyé"}

    except Exception as e:
        print("❌ Exception webhook:", e)
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


# ========================
# RESET PASSWORD (demande lien)
# ========================
@app.post("/reset-password")
def reset_password_request(email: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(AdminUser).filter(AdminUser.email == email).first()
    if not user:
        return {"success": False, "message": "Aucun compte associé à cet email."}

    # 🚫 NE PAS autoriser le reset si le compte n'est pas activé
    if not user.is_active:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "error": "inactive_account",
                "message": "Compte non activé. Demandez un nouveau lien d’activation.",
            },
        )

    # Générer un token de reset valable 1h
    token = str(uuid.uuid4())
    user.token = token
    user.token_expiry = utcnow() + timedelta(hours=1)
    db.commit()

    reset_link = f"{BASE_PUBLIC_URL}/static/reset_password_confirm.html?token={token}"

    try:
        msg = MIMEMultipart()
        msg["From"] = SMTP_USER
        msg["To"] = email
        msg["Subject"] = "Réinitialisation de ton mot de passe"
        body = f"""
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>Réinitialisation de mot de passe</title>
</head>
<body style="font-family: Arial, sans-serif; background:#f4f4f4; padding:20px; color:#333;">
  <table align="center" width="100%" style="max-width:600px; background:#ffffff; border-radius:8px; box-shadow:0 2px 5px rgba(0,0,0,0.1);">
    <tr>
      <td style="text-align:center; padding:20px;">
        <img src="https://via.placeholder.com/150x50?text=QR Event+Logo" alt="QR Event Logo" style="max-width:150px;">
      </td>
    </tr>
    <tr>
      <td style="padding:20px; font-size:16px; line-height:1.5;">
        <h2 style="color:#007bff; text-align:center;">Réinitialisation de votre mot de passe</h2>
        <p>Bonjour,</p>
        <p>Vous avez demandé à réinitialiser votre mot de passe pour accéder à votre compte administrateur QR Event.</p>
        <p>Veuillez cliquer sur le bouton ci-dessous pour choisir un nouveau mot de passe :</p>

        <p style="text-align:center; margin:30px 0;">
          <a href="{reset_link}" style="background:#007bff; color:#ffffff; padding:12px 24px; text-decoration:none; border-radius:6px; font-weight:bold;">
            🔑 Réinitialiser mon mot de passe
          </a>
        </p>

        <p>Si le bouton ne fonctionne pas, copiez-collez ce lien dans votre navigateur :</p>
        <p style="word-break:break-all; color:#555;">{reset_link}</p>

        <p>Ce lien expirera dans 1 heure pour des raisons de sécurité.</p>
        <p>À très vite,<br>L’équipe QR Event 🚀</p>
      </td>
    </tr>
  </table>
</body>
</html>
        """
        msg.attach(MIMEText(body, "html"))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, email, msg.as_string())
        server.quit()

        return {"success": True, "message": "Email envoyé"}
    except Exception as e:
        print("❌ Erreur reset-password:", e)
        traceback.print_exc()
        return {"success": False, "message": "Impossible d’envoyer l’email."}


# ========================
# RESET PASSWORD CONFIRM (nouveau mot de passe)
# ========================
@app.post("/reset-password/confirm")
def reset_password_confirm(token: str = Form(...), new_password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not user or not user.token_expiry or utcnow() > user.token_expiry:
        return {"success": False, "message": "Lien invalide ou expiré."}

    # 🚫 NE PAS autoriser la confirmation si le compte n'est pas activé
    if not user.is_active:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "error": "inactive_account",
                "message": "Compte non activé. Utilisez le lien d’activation.",
            },
        )

    # 🚫 Empêche de réutiliser le mot de passe actuel
    if is_password_reused(user, new_password):
        return JSONResponse(
            status_code=409,
            content={"success": False, "error": "Mot de passe déjà utilisé. Choisissez-en un différent."}
        )

    # ✅ Validation force minimale du mot de passe
    pwd = new_password.strip()
    if len(pwd) < 8 or \
       not re.search(r"[A-Z]", pwd) or \
       not re.search(r"[a-z]", pwd) or \
       not re.search(r"[0-9]", pwd):
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": "Mot de passe trop faible (min. 8 car., 1 maj, 1 min, 1 chiffre)."}
        )

    user.password_hash = bcrypt.hash(new_password)
    user.token = None
    user.token_expiry = None
    db.commit()

    return {"success": True, "message": "Mot de passe mis à jour avec succès."}

# ========================
# ADMIN LOGS
# ========================
@app.post("/admin/logs")
def get_logs(token: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not check_token_valid(user, db):
        return {"success": False, "message": "Non autorisé"}

    logs = db.query(AdminLog).filter(AdminLog.admin_id == user.id).order_by(AdminLog.created_at.desc()).all()

    return {
        "success": True,
        "logs": [
            {"action": l.action, "details": l.details, "date": l.created_at.strftime("%Y-%m-%d %H:%M:%S")}
            for l in logs
        ]
    }

# ==============================
# API - CREDITS DISPONIBLES
# ==============================
@app.get("/api/license/credits")
def get_license_credits(event_id: int = None, db: Session = Depends(get_db)):
    # Si on fournit un event_id → on récupère l'admin qui a créé cet event
    if event_id:
        event = db.query(Event).filter(Event.id == event_id).first()
        if not event:
            return {"remaining_participant_credits": 0}
        admin = db.query(AdminUser).filter(AdminUser.id == event.created_by).first()
        if not admin:
            return {"remaining_participant_credits": 0}
        return {"remaining_participant_credits": max(0, admin.participant_credits)}

    # Sinon, fallback (ancien comportement) → premier admin actif
    license_owner = db.query(AdminUser).filter_by(is_active=True).first()
    if not license_owner:
        return {"remaining_participant_credits": 0}

    return {"remaining_participant_credits": max(0, license_owner.participant_credits)}

# ========================
# CHECK-IN : RECHERCHE PARTICIPANTS
# ========================
@app.post("/checkin/search")
def checkin_search(
    event_id: int = Form(...),
    q: Optional[str] = Form(""),
    db: Session = Depends(get_db)
):
    qry = db.query(Participant).filter(Participant.event_id == event_id)

    if q:
        like = f"%{q.strip()}%"
        qry = qry.filter(
            (Participant.name.ilike(like)) |
            (Participant.email.ilike(like))
        )

    rows = qry.order_by(Participant.name.asc()).limit(50).all()

    results = []
    for p in rows:
        parts = (p.name or "").split()
        first_name = parts[0] if parts else ""
        last_name  = " ".join(parts[1:]) if len(parts) > 1 else ""
        results.append({
            "id": p.id,
            "qr_code": getattr(p, "qr_code", None),
            "first_name": first_name,
            "last_name": last_name,
            "email": p.email,
            "amount_paid": getattr(p, "amount", None),
            "scanned": bool(getattr(p, "scanned", False)),
        })

    return {"success": True, "participants": results}

# ========================
# ADMIN : AJOUT PARTICIPANTS
# ========================
@app.post("/api/manual-registration")
def manual_registration(
    background_tasks: BackgroundTasks,
    data: dict = Body(...),
    db: Session = Depends(get_db)
):
    token = data.get("token")
    if not token:
        return {"success": False, "message": "Token manquant"}

    # 1) Vérifier l’admin via token
    admin = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not check_token_valid(admin, db):
        return {"success": False, "message": "Session invalide"}

    # 2) Vérifier mot de passe admin
    if not bcrypt.verify(data.get("admin_password", ""), admin.password_hash):
        return {"success": False, "message": "Mot de passe admin incorrect"}

    # 3) Cast event_id et amount (évite 422)
    try:
        event_id = int(data.get("event_id"))
        amount = float(data.get("amount", 0))
    except (TypeError, ValueError):
        return {"success": False, "message": "Paramètres invalides"}

    # 4) Vérifier l’événement
    event = db.query(Event).filter(Event.id == event_id, Event.is_active == True).first()
    if not event:
        return {"success": False, "message": "Événement introuvable ou inactif"}

    # 5) Vérifier crédits
    if admin.participant_credits <= 0:
        return {"success": False, "message": "⚠️ Pas assez de crédits disponibles"}

    # 6) Vérifier quota
    participants_count = db.query(Participant).filter(Participant.event_id == event.id).count()
    if event.max_participants and participants_count >= event.max_participants:
        return {"success": False, "message": "⚠️ Événement complet"}

    # 7) Préparer les infos participant
    safe_first = html.escape(data["first_name"].strip())
    safe_last = html.escape(data["last_name"].strip())
    safe_name = f"{safe_first} {safe_last}".strip() or "Participant"
    safe_email = html.escape(data["email"].strip().lower())

    qr_code_value = str(uuid.uuid4())
    participant = Participant(
        name=safe_name,
        email=safe_email,
        event_id=event_id,
        amount=amount,
        transaction_id=f"manual-{uuid.uuid4()}",
        qr_code=qr_code_value,
        created_at=utcnow()
    )

    db.add(participant)

    # Décrément crédits
    admin.participant_credits -= 1
    db.commit()
    db.refresh(participant)

    # 8) Générer QR data
    qr_token = participant.qr_code or str(participant.id)
    qr_data = f"{BASE_PUBLIC_URL}/api/event/{event.id}?participant={qr_token}"

    # 9) Envoi email confirmation (async)
    background_tasks.add_task(
        send_confirmation_email,
        recipient_email=safe_email,
        subject=f"Confirmation inscription - {event.title}",
        participant=participant,
        event=event,
        qr_data=qr_data
    )

    return {"success": True, "message": "✅ Participant ajouté manuellement et email envoyé"}


@app.get("/api/config/maps-key")
def get_maps_key():
    return JSONResponse({"key": os.getenv("GOOGLE_MAPS_API_KEY")})


@app.get("/api/tinymce-key")
async def get_tinymce_key():
    key = os.getenv("TINYMCE_API_KEY", "")
    return JSONResponse({"key": key})
