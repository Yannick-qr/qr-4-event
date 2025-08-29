from fastapi import FastAPI, Depends, HTTPException, Form, Request, Body
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse, StreamingResponse
from sqlalchemy.orm import Session
from database import Base, engine, get_db, AdminUser, Event, EventRegistration, Participant, AdminLog
from passlib.hash import bcrypt
from datetime import datetime, timedelta
from fastapi import UploadFile, File
import shutil
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
import requests
import json
import csv
import html
import re
import traceback

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

# ========================
# APP INIT
# ========================
app = FastAPI()

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
def send_email_with_qr(to_email: str, subject: str, html_content: str, qr_data: str):
    try:
        msg = MIMEMultipart("mixed")
        msg["From"] = SMTP_USER
        msg["To"] = to_email
        msg["Subject"] = subject

        msg.attach(MIMEText(html_content, "html"))

        qr = qrcode.make(qr_data)
        img_bytes = io.BytesIO()
        qr.save(img_bytes, format="PNG")
        img_bytes.seek(0)

        part = MIMEBase("application", "octet-stream")
        part.set_payload(img_bytes.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", 'attachment; filename="qrcode.png"')
        msg.attach(part)

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, to_email, msg.as_string())
        server.quit()
    except Exception as e:
        import traceback
        print("❌ Erreur SMTP (QR):", e)
        traceback.print_exc()   # 👈 ça affichera la stack complète dans la console

def check_token_valid(user: AdminUser, db: Session):
    if not user or not user.token:
        return False
    if not user.token_expiry or datetime.utcnow() > user.token_expiry:
        user.token = None
        user.token_expiry = None
        db.commit()
        return False
    return True

def log_admin_action(db: Session, admin_id: int, action: str, details: str = None):
    new_log = AdminLog(admin_id=admin_id, action=action, details=details)
    db.add(new_log)
    db.commit()


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
    expiry = datetime.utcnow() + timedelta(hours=24)
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
    prenom: str = Form(""),
    nom: str = Form(""),
    email: str = Form(...),
    db: Session = Depends(get_db)
):
    # 🧹 Nettoyage des entrées
    prenom = html.escape(prenom.strip())
    nom = html.escape(nom.strip())
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
    expiry = datetime.utcnow() + timedelta(hours=48)

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

    body = f"""
    <h2>Bienvenue sur QR Event 🎉</h2>
    <p>Ton paiement est confirmé ✅</p>
    <p>Voici ton lien pour définir ton mot de passe (valable 48h) :</p>
    <p><a href="{verify_link}">Définir mon mot de passe</a></p>
    """

    try:
        send_email_with_qr(email, "Définir ton mot de passe - QR Event", body, qr_data=verify_link)
    except Exception as e:
        print("❌ Erreur lors de l’envoi du mail d’activation :", e)
        traceback.print_exc()

    return {
        "success": True,
        "message": "Paiement confirmé, email envoyé avec lien pour définir le mot de passe."
    }

# ========================
# SET PASSWORD
# ========================
@app.post("/set-password")
def set_password(token: str = Form(...), new_password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not user or datetime.utcnow() > user.token_expiry:
        return {"success": False, "message": "Token invalide ou expiré"}

    user.password_hash = bcrypt.hash(new_password)
    user.is_active = True
    user.token = None
    user.token_expiry = None
    db.commit()

    return {"success": True, "message": "Mot de passe défini, vous pouvez maintenant vous connecter."}


# ========================
# BUY EVENT CREDITS (ajout après paiement validé)
# ========================
@app.post("/buy-credits")
def buy_credits(token: str = Form(...), quantity: int = Form(...), db: Session = Depends(get_db)):
    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not check_token_valid(user, db):
        return {"success": False, "message": "Session invalide"}

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
            amount = LICENSE_PRICE   # 👈 pris du .env

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


        # 🔹 Étape 1 : Authentification OAuth PayPal
        auth_req = requests.post(
            f"{PAYPAL_API_BASE}/v1/oauth2/token",
            headers={"Accept": "application/json", "Accept-Language": "en_US"},
            data={"grant_type": "client_credentials"},
            auth=(PAYPAL_CLIENT_ID, PAYPAL_SECRET)
        )

        if auth_req.status_code != 200:
            return {"success": False, "message": "OAuth failed", "paypal_response": auth_req.text}

        access_token = auth_req.json().get("access_token")
        if not access_token:
            return {"success": False, "message": "Pas de access_token", "paypal_response": auth_req.json()}

        # 🔹 Étape 2 : Créer la commande PayPal
        order_req = requests.post(
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
            }
        )

        order_data = order_req.json()

        if "id" not in order_data:
            return {"success": False, "message": "PayPal n’a pas renvoyé d’ID", "paypal_response": order_data}

        return {"success": True, "id": order_data["id"], "paypal_response": order_data}

    except Exception as e:
        import traceback
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

    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not user:
        return {"success": False, "message": "Utilisateur non trouvé ou session expirée"}

    if credits <= 0:
        return {"success": False, "message": "Crédits invalides"}

    # Ajouter les crédits
    user.participant_credits += credits
    db.commit()

    return {"success": True, "new_credits": user.participant_credits}

# ========================
# REGISTER PARTICIPANT (après paiement réussi)
# ========================
@app.post("/register_participant")
def register_participant(
    name: str = Form(...),
    email: str = Form(...),
    event_id: int = Form(...),
    amount: float = Form(...),
    transaction_id: str = Form(...),
    db: Session = Depends(get_db)
):
    try:
        # 🔒 Nettoyage des entrées
        safe_name = html.escape(re.sub(r"[<>]", "", name.strip()))
        safe_email = html.escape(email.strip().lower())

        # Validation email simple
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", safe_email):
            return {"success": False, "message": "❌ Email invalide."}

        # Vérifie si l'événement existe
        event = db.query(Event).filter(Event.id == event_id, Event.is_active == True).first()
        if not event:
            return {"success": False, "message": "❌ Événement introuvable ou inactif."}

        # Vérifie si l'événement a atteint sa limite de participants
        participants_count = db.query(Participant).filter(Participant.event_id == event.id).count()
        if event.max_participants and participants_count >= event.max_participants:
            return {"success": False, "message": "⚠️ Événement complet."}

        # Vérifie si déjà inscrit avec cette transaction
        existing = db.query(Participant).filter(Participant.transaction_id == transaction_id).first()
        if existing:
            return {"success": True, "message": "ℹ️ Déjà enregistré."}

        # Vérifie si l'admin a encore des crédits
        admin = db.query(AdminUser).filter(AdminUser.id == event.created_by).first()
        if not admin:
            return {"success": False, "message": "❌ Admin introuvable pour cet événement."}
        if admin.participant_credits <= 0:
            return {"success": False, "message": "⚠️ Pas assez de crédits participants."}

        # ✅ Crée le participant
        participant = Participant(
            name=safe_name,
            email=safe_email,
            event_id=event_id,
            amount=amount,
            transaction_id=transaction_id,
            created_at=datetime.utcnow()
        )
        db.add(participant)

        # 🔑 Décrémentation des crédits participants
        admin.participant_credits -= 1
        db.commit()
        db.refresh(participant)

        # ✅ Génère QR code et envoie email
        qr_data = f"{BASE_PUBLIC_URL}/api/event/{event_id}?participant={participant.id}"
        body = f"""
        <h2>Inscription confirmée 🎉</h2>
        <p>Merci {safe_name}, ton paiement de {amount} € pour l’événement <b>{event.title}</b> a bien été enregistré.</p>
        <p>Date : {event.date} – Lieu : {event.location}</p>
        <p>Ton QR code est en pièce jointe, il te sera demandé à l’entrée ✅</p>
        """

        try:
            send_email_with_qr(safe_email, f"Confirmation inscription - {event.title}", body, qr_data=qr_data)
        except Exception as e:
            print("❌ Erreur lors de l’envoi du mail participant :", e)

        return {"success": True, "message": "🎉 Inscription enregistrée avec succès, email envoyé."}

    except Exception as e:
        import traceback
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
    return {
        "success": True,
        "email": user.email,
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
    image: UploadFile = File(None),   # ✅ nouveau
    db: Session = Depends(get_db)
):
    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not check_token_valid(user, db):
        return {"success": False, "message": "Non autorisé"}

    # ✅ Sauvegarde image
    image_url = None
    if image:
        os.makedirs("static/uploads", exist_ok=True)
        file_path = os.path.join("static/uploads", f"{uuid.uuid4()}_{image.filename}")
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(image.file, buffer)
        image_url = "/" + file_path

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
        image_url=image_url  # ✅ enregistré
    )
    db.add(new_event)
    db.commit()
    db.refresh(new_event)

    return {"success": True, "event_id": new_event.id, "image_url": image_url}


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
    event = db.query(Event).filter(Event.id == event_id, Event.created_by == user.id).first()
    if not event:
        return {"success": False, "message": "Événement introuvable"}

    event.title = title
    event.description = description
    event.date = date
    event.location = location
    event.price = price
    event.checkin_login = checkin_login
    event.checkin_password = checkin_password
    event.max_participants = max_participants

    # ✅ Met à jour image si uploadée
    if image:
        os.makedirs("static/uploads", exist_ok=True)
        file_path = os.path.join("static/uploads", f"{uuid.uuid4()}_{image.filename}")
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(image.file, buffer)
        event.image_url = "/" + file_path

    db.commit()
    return {"success": True, "message": "Événement mis à jour", "image_url": event.image_url}



@app.post("/admin/events/delete")
def delete_event(event_id: int = Form(...), token: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    event = db.query(Event).filter(Event.id == event_id, Event.created_by == user.id).first()
    if not event:
        return {"success": False, "message": "Événement introuvable"}

    db.delete(event)
    db.commit()
    return {"success": True, "message": "Événement supprimé"}


@app.post("/admin/events/toggle")
def toggle_event(event_id: int = Form(...), token: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    event = db.query(Event).filter(Event.id == event_id, Event.created_by == user.id).first()
    if not event:
        return {"success": False, "message": "Événement introuvable"}

    event.is_active = not event.is_active
    db.commit()
    return {"success": True, "is_active": event.is_active}


from fastapi.responses import HTMLResponse

@app.get("/event/{event_id}", response_class=HTMLResponse)
def public_event(event_id: int, db: Session = Depends(get_db)):
    event = db.query(Event).filter(Event.id == event_id, Event.is_active == True).first()
    if not event:
        return HTMLResponse("<h2>Événement introuvable ou inactif ❌</h2>", status_code=404)

    return f"""
    <html>
    <head>
        <title>{event.title} - QR Event</title>
    </head>
    <body style="font-family: Arial, sans-serif; background: #f5f6fa; padding:20px;">
        <h1>{event.title}</h1>
        <p><b>Description :</b> {event.description}</p>
        <p><b>Date :</b> {event.date}</p>
        <p><b>Lieu :</b> {event.location}</p>
        <p><b>Prix :</b> {event.price} €</p>
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
def api_event(event_id: int, db: Session = Depends(get_db)):
    event = db.query(Event).filter(Event.id == event_id, Event.is_active == True).first()
    if not event:
        return JSONResponse(status_code=404, content={"success": False, "message": "Événement introuvable ou inactif"})

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
            "max_participants": event.max_participants,   # ✅ ajouté
            "participants_count": participants_count,     # ✅ ajouté
            "public_url": f"{BASE_PUBLIC_URL}/static/event.html?id={event.id}",
            # ✅ ajoute ça :
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
        event = db.query(Event).filter(Event.id == event_id, Event.is_active == True).first()
        if not event:
            # ⚠️ Toujours renvoyer un id, même si None
            return {"id": None, "message": "❌ Événement introuvable ou inactif"}


        # Récupère l'admin créateur
        admin = db.query(AdminUser).filter(AdminUser.id == event.created_by).first()

        # Choisit les credentials PayPal
        client_id = admin.paypal_client_id if admin and admin.paypal_client_id else PAYPAL_CLIENT_ID
        secret = admin.paypal_secret if admin and admin.paypal_secret else PAYPAL_SECRET

        # 🔹 Authentification PayPal
        auth_req = requests.post(
            f"{PAYPAL_API_BASE}/v1/oauth2/token",
            headers={"Accept": "application/json", "Accept-Language": "en_US"},
            data={"grant_type": "client_credentials"},
            auth=(client_id, secret)
        )

        if auth_req.status_code != 200:
            return {"id": None, "message": "❌ OAuth PayPal échoué", "paypal_response": auth_req.text}


        access_token = auth_req.json().get("access_token")
        if not access_token:
            return {"id": None, "message": "Pas de access_token", "paypal_response": auth_req.json()}

        # 🔹 Crée la commande PayPal (montant = prix de l’événement)
        order_req = requests.post(
            f"{PAYPAL_API_BASE}/v2/checkout/orders",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}"
            },
            json={
                "intent": "CAPTURE",
                "purchase_units": [{
                    "reference_id": str(event.id),  # utile dans webhook
                    "amount": {
                        "currency_code": "EUR",
                        "value": str(event.price)
                    }
                }]
            }
        )

        order_data = order_req.json()

        if "id" not in order_data:
            return {"id": None, "message": "PayPal n’a pas renvoyé d’ID", "paypal_response": order_data}

        # ✅ Retour toujours au format attendu par PayPal SDK
        return {"id": order_data["id"]}

    except Exception as e:
        import traceback
        print("❌ Exception event_pay:", e)
        traceback.print_exc()
        return {"id": None, "message": str(e)}



# ========================
# LIST EVENTS
# ========================
@app.post("/admin/events/list")
def list_events(token: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not check_token_valid(user, db):
        return {"success": False, "message": "Non autorisé"}

    events = db.query(Event).filter(Event.created_by == user.id).all()

    return {
        "success": True,
	"participant_credits": user.participant_credits,
        "events": [
            {
                "id": e.id,
                "title": e.title,
                "description": e.description,
                "date": e.date,
                "location": e.location,
                "price": e.price,
                "checkin_login": e.checkin_login,          # ✅ ajouté
                "checkin_password": e.checkin_password,    # ✅ ajouté
                "is_active": e.is_active,
                "is_locked": e.is_locked,
                "max_participants": e.max_participants,
                "image_url": e.image_url,   # ✅ ajout ici
                "public_url": f"{BASE_PUBLIC_URL}/static/event.html?id={e.id}"
            }
            for e in events
        ]
    }

# ========================
# ADMIN : INSCRIPTIONS PAYÉES
# ========================
from fastapi.responses import StreamingResponse
import csv

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
# CHECK-IN (Scan Event)
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


@app.post("/checkin/scan")
def checkin_scan(
    event_id: int = Form(...),
    qr_code: str = Form(...),
    db: Session = Depends(get_db)
):
    participant = db.query(Participant).filter(
        Participant.event_id == event_id,
        Participant.id == qr_code   # ⚠️ à adapter si ton QR code contient autre chose
    ).first()

    if not participant:
        return {"success": False, "message": "QR code invalide ou participant introuvable"}

    event = db.query(Event).filter(Event.id == event_id).first()

    return {
        "success": True,
        "participant": {
            "first_name": participant.name.split(" ")[0] if participant.name else "",
            "last_name": " ".join(participant.name.split(" ")[1:]) if participant.name else "",
            "email": participant.email,
            "amount_paid": participant.amount,
            "event_title": event.title,
            "date": event.date,
            "location": event.location,
            "scanned": participant.scanned
        }
    }


@app.post("/checkin/validate")
def checkin_validate(
    event_id: int = Form(...),
    qr_code: str = Form(...),
    db: Session = Depends(get_db)
):
    participant = db.query(Participant).filter(
        Participant.event_id == event_id,
        Participant.id == qr_code
    ).first()

    if not participant:
        return {"success": False, "message": "Participant introuvable"}

    if participant.scanned:
        return {"success": False, "message": "⚠️ Déjà scanné à " + str(participant.scanned_at)}

    participant.scanned = True
    participant.scanned_at = datetime.utcnow()
    db.commit()

    return {"success": True, "message": f"✅ Check-in validé pour {participant.name}"}

# ========================
# WEBHOOK PAYPAL
# ========================
@app.post("/paypal/webhook")
async def paypal_webhook(request: Request, db: Session = Depends(get_db)):
    try:
        body = await request.body()
        headers = request.headers

        # Charger une seule fois le JSON
        event = json.loads(body)

        # Vérification de la signature PayPal
        verify_url = f"{PAYPAL_API_BASE}/v1/notifications/verify-webhook-signature"
        auth = (PAYPAL_CLIENT_ID, PAYPAL_SECRET)

        payload = {
            "transmission_id": headers.get("Paypal-Transmission-Id"),
            "transmission_time": headers.get("Paypal-Transmission-Time"),
            "cert_url": headers.get("Paypal-Cert-Url"),
            "auth_algo": headers.get("Paypal-Auth-Algo"),
            "transmission_sig": headers.get("Paypal-Transmission-Sig"),
            "webhook_id": PAYPAL_WEBHOOK_ID,
            "webhook_event": event   # ✅ objet JSON et pas string
        }

        r = requests.post(verify_url, auth=auth, json=payload)
        verification = r.json()
        print("🔎 Résultat vérification PayPal:", verification)

        if verification.get("verification_status") != "SUCCESS":
            print("❌ Signature PayPal invalide :", verification)
            return JSONResponse(status_code=400, content={"success": False, "message": "Signature invalide"})

        # Lecture de l’événement
        event_type = event.get("event_type")

        # 🟢 DEBUG : log l’événement reçu
        print(f"📩 Webhook PayPal reçu : type={event_type}")
        print(f"Payload complet reçu : {event}")

        # On gère les deux types d’events
        if event_type in ["CHECKOUT.ORDER.APPROVED", "PAYMENT.CAPTURE.COMPLETED"]:
            payer_email = event["resource"]["payer"]["email_address"]
            payment_id = event["resource"]["id"]

            print(f"✅ Paiement détecté : payment_id={payment_id}, email={payer_email}")

            # Récupérer l’event_id
            try:
                event_id = int(event["resource"]["purchase_units"][0]["reference_id"])
                print(f"🎟️ Inscription liée à l’événement ID={event_id}")
            except Exception:
                print("⚠️ event_id manquant dans reference_id")
                return {"success": False, "message": "event_id manquant dans purchase_units.reference_id"}

            # Vérifie si déjà inscrit
            existing = db.query(EventRegistration).filter_by(payment_id=payment_id).first()
            if existing:
                print("ℹ️ Paiement déjà enregistré (ignorer).")
                return {"success": True, "message": "Paiement déjà enregistré"}

            existing_participant = db.query(Participant).filter_by(transaction_id=payment_id).first()
            if existing_participant:
                print("ℹ️ Participant déjà créé (ignorer).")
                return {"success": True, "message": "Participant déjà enregistré"}

            # Vérifie l'événement
            event_db = db.query(Event).filter(Event.id == event_id).first()
            if not event_db:
                print("❌ Événement introuvable en DB")
                return {"success": False, "message": "Événement introuvable"}

            # Vérifie si l'événement a atteint sa limite de participants
            participants_count = db.query(Participant).filter(Participant.event_id == event_db.id).count()
            if event_db.max_participants and participants_count >= event_db.max_participants:
               print("⚠️ Paiement reçu mais event complet → refus")
               return {"success": False, "message": "Événement complet"}

            # Enregistrement DB
            new_reg = EventRegistration(
                user_id=None,
                event_id=event_id,
                payment_id=payment_id
            )
            db.add(new_reg)

            participant = Participant(
                name=payer_email.split("@")[0],
                email=payer_email,
                amount=float(event["resource"]["amount"]["value"]) if "amount" in event["resource"] else event_db.price,
                transaction_id=payment_id,
                event_id=event_id,
                created_at=datetime.utcnow()
            )
            db.add(participant)

            # 🔑 Décrémentation des crédits participants
            admin = db.query(AdminUser).filter(AdminUser.id == event_db.created_by).first()
            if not admin:
                return {"success": False, "message": "Admin introuvable pour cet événement."}
            if admin.participant_credits <= 0:
                return {"success": False, "message": "Pas assez de crédits participants"}
            admin.participant_credits -= 1


            # Envoi email
            qr_data = f"{BASE_PUBLIC_URL}/api/event/{event_id}?participant={participant.id}"
            body = f"""
            <h2>Inscription confirmée 🎉</h2>
            <p>Merci {participant.email}, ton paiement de {participant.amount} € pour l’événement <b>{event_db.title}</b> a bien été enregistré.</p>
            <p>Date : {event_db.date} – Lieu : {event_db.location}</p>
            <p>Ton QR code est en pièce jointe, il te sera demandé à l’entrée ✅</p>
            """

            try:
                send_email_with_qr(participant.email, f"Confirmation inscription - {event_db.title}", body, qr_data=qr_data)
                print(f"📧 Email envoyé à {participant.email}")
            except Exception as e:
                print("❌ Erreur envoi email participant :", e)

            db.commit()

            return {"success": True, "message": "Inscription validée et enregistrée."}

        # Si un autre event PayPal arrive
        print(f"ℹ️ Webhook ignoré : {event_type}")
        return {"success": True, "message": f"Webhook reçu ({event_type}) mais ignoré"}

    except Exception as e:
        import traceback
        print("❌ Exception webhook PayPal:", e)
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"success": False, "message": f"❌ Erreur serveur : {str(e)}"})



# ========================
# RESET PASSWORD (demande lien)
# ========================
@app.post("/reset-password")
def reset_password_request(email: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(AdminUser).filter(AdminUser.email == email).first()
    if not user:
        return {"success": False, "message": "Aucun compte associé à cet email."}

    # Générer un token de reset valable 1h
    token = str(uuid.uuid4())
    user.token = token
    user.token_expiry = datetime.utcnow() + timedelta(hours=1)
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
        import traceback
        print("❌ Erreur reset-password:", e)
        traceback.print_exc()
        return {"success": False, "message": "Impossible d’envoyer l’email."}


# ========================
# RESET PASSWORD CONFIRM (nouveau mot de passe)
# ========================
@app.post("/reset-password/confirm")
def reset_password_confirm(token: str = Form(...), new_password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(AdminUser).filter(AdminUser.token == token).first()
    if not user or not user.token_expiry or datetime.utcnow() > user.token_expiry:
        return {"success": False, "message": "Lien invalide ou expiré."}

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

