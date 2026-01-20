import pytest
import jwt
from datetime import datetime, timedelta
from fastapi import HTTPException
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.auth.jwt_handler import create_access_token, verify_token, extract_user_id_from_token_payload, is_token_expired
from src.config.settings import settings


def test_create_access_token():
    """Test creating a valid JWT token"""
    data = {"sub": "user123", "email": "test@example.com"}
    token = create_access_token(data)

    assert token is not None
    assert isinstance(token, str)
    assert len(token) > 0


def test_verify_valid_token():
    """Test verifying a valid JWT token"""
    data = {"sub": "user123", "email": "test@example.com"}
    token = create_access_token(data)

    payload = verify_token(token)

    assert payload is not None
    assert payload["sub"] == "user123"
    assert payload["email"] == "test@example.com"


def test_verify_expired_token():
    """Test verifying an expired JWT token raises HTTPException"""
    data = {"sub": "user123", "email": "test@example.com"}
    # Create a token that expired 1 hour ago
    expired_data = {**data, "exp": (datetime.utcnow() - timedelta(hours=1)).timestamp()}
    token = jwt.encode(expired_data, settings.better_auth_secret, algorithm=settings.jwt_algorithm)

    with pytest.raises(HTTPException) as exc_info:
        verify_token(token)

    assert exc_info.value.status_code == 401
    assert "expired" in exc_info.value.detail.lower()


def test_verify_invalid_token():
    """Test verifying an invalid JWT token raises HTTPException"""
    invalid_token = "invalid.token.string"

    with pytest.raises(HTTPException) as exc_info:
        verify_token(invalid_token)

    assert exc_info.value.status_code == 401
    assert "invalid" in exc_info.value.detail.lower()


def test_extract_user_id_from_payload():
    """Test extracting user ID from token payload"""
    payload = {"sub": "user123", "email": "test@example.com"}

    user_id = extract_user_id_from_token_payload(payload)

    assert user_id == "user123"


def test_extract_user_id_missing():
    """Test extracting user ID when not present raises HTTPException"""
    payload = {"email": "test@example.com"}  # No user ID field

    with pytest.raises(HTTPException) as exc_info:
        extract_user_id_from_token_payload(payload)

    assert exc_info.value.status_code == 401


def test_is_token_expired():
    """Test checking if a token is expired"""
    # Valid token (not expired)
    payload = {
        "sub": "user123",
        "exp": (datetime.utcnow() + timedelta(hours=1)).timestamp()
    }
    assert is_token_expired(payload) is False

    # Expired token
    payload = {
        "sub": "user123",
        "exp": (datetime.utcnow() - timedelta(hours=1)).timestamp()
    }
    assert is_token_expired(payload) is True

    # Token without exp field
    payload = {"sub": "user123"}
    assert is_token_expired(payload) is True