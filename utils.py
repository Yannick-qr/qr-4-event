# utils.py
from datetime import datetime

def check_token_valid(user, db):
    """
    Vérifie si le token de l'utilisateur admin est encore valide.
    
    :param user: objet AdminUser récupéré via SQLAlchemy
    :param db: session SQLAlchemy (non utilisée ici, mais laissée pour compatibilité)
    :return: True si valide, False sinon
    """
    if not user:
        return False

    # Vérifie que le token n'est pas expiré
    if not user.token_expiry or user.token_expiry < datetime.utcnow():
        return False

    return True
