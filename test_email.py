import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

# Charger ton fichier .env
load_dotenv()

SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
FROM_EMAIL = os.getenv("FROM_EMAIL")

def send_test_email():
    try:
        # Préparer l’email
        msg = MIMEText("<h2>Test réussi !</h2><p>Ceci est un test depuis noreply@qr4event.com</p>", "html")
        msg["From"] = FROM_EMAIL
        msg["To"] = "tessany.yannick@outlook.fr"  # 👉 mets ton adresse perso ici
        msg["Subject"] = "Test OVH Zimbra - QR Event"

        # Connexion SMTP OVH
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(FROM_EMAIL, "tessany.yannick@outlook.fr", msg.as_string())

        print("Email de test envoyé avec succès !")
    except Exception as e:
        print("Erreur :", e)

# Lancer le test
send_test_email()
