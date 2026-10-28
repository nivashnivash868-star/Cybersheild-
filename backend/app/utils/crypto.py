import base64
import hashlib
import hmac
from cryptography.fernet import Fernet, InvalidToken
from app.config import settings


def _key(purpose: str) -> bytes:
    return hmac.new(settings.SECRET_KEY.encode(), purpose.encode(), hashlib.sha256).digest()


def hmac_hex(purpose: str, message: str) -> str:
    return hmac.new(_key(purpose), message.encode(), hashlib.sha256).hexdigest()


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _fernet() -> Fernet:
    return Fernet(base64.urlsafe_b64encode(_key("fernet-v1")))


def encrypt_text(plain: str) -> str:
    return _fernet().encrypt(plain.encode()).decode()


def decrypt_text(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("Stored secret cannot be decrypted with the current SECRET_KEY.") from exc
