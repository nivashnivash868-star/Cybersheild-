import pytest
from app.utils.auth import get_password_hash, verify_password, create_access_token, decode_access_token

def test_password_hashing():
    pwd = "SecureP@ssword2026!"
    hashed = get_password_hash(pwd)
    assert hashed != pwd
    assert verify_password(pwd, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False

def test_jwt_token_generation_and_decoding():
    data = {"sub": "analyst@cybershield.corp", "role": "SOC Analyst", "name": "Sarah Chen"}
    token = create_access_token(data)
    assert isinstance(token, str)
    decoded = decode_access_token(token)
    assert decoded is not None
    assert decoded["sub"] == "analyst@cybershield.corp"
    assert decoded["role"] == "SOC Analyst"
