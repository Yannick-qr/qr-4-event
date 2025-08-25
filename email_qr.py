import os, io, qrcode, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from dotenv import load_dotenv
from pathlib import Path

# Forcer à charger le bon fichier .env
load_dotenv(dotenv_path=Path("C:/Users/tessa/OneDrive/Bureau/Application/pay-qr-app/.env"))

SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT   = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER   = os.getenv("SMTP_USER")
SMTP_PASS   = os.getenv("SMTP_PASS")
FROM_EMAIL  = os.getenv("FROM_EMAIL", SMTP_USER)

def send_qr_email(to_email: str, subject: str, message: str, qr_payload: str):
    # 1) Générer le QR
    img = qrcode.make(qr_payload)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    # 2) Construire le mail
    msg = MIMEMultipart()
    msg["From"] = FROM_EMAIL
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(message, "plain", "utf-8"))

    part = MIMEBase('application', 'octet-stream')
    part.set_payload(buf.read())
    encoders.encode_base64(part)
    part.add_header('Content-Disposition', 'attachment; filename="qr.png"')
    msg.attach(part)

    # 3) Envoyer
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as s:
        s.starttls()
        print("Connexion SMTP avec :", SMTP_USER)  # Debug
        s.login(SMTP_USER, SMTP_PASS)
        s.sendmail(FROM_EMAIL, [to_email], msg.as_string())
