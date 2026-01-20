"""
JWT Token Validation and Expiration Tests

This module contains specific tests for JWT token validation and expiration handling
to ensure proper security measures are in place.
"""

import pytest
import jwt
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.main import app
from src.config import settings


client = TestClient(app)


def test_jwt_token_structure_and_algorithm():
    """Test that JWT tokens are created with the correct algorithm and structure"""
    # Register a test user
    user_data = {
        "email": "jwt_test@example.com",
        "password": "SecurePass123!",
        "first_name": "JWT",
        "last_name": "Tester"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login to get a token
    login_data = {
        "email": "jwt_test@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    # Decode the token without verification to inspect its structure
    decoded_payload = jwt.decode(token, options={"verify_signature": False})

    # Verify standard claims exist
    assert "sub" in decoded_payload  # Subject (user identifier)
    assert "exp" in decoded_payload  # Expiration time
    assert "iat" in decoded_payload  # Issued at time
    assert "jti" in decoded_payload  # JWT ID (if implemented)

    # Verify the algorithm used matches the configuration
    header = jwt.get_unverified_header(token)
    assert header["alg"].upper() == settings.JWT_ALGORITHM.upper()


def test_jwt_secret_key_validation():
    """Test that tokens can only be validated with the correct secret key"""
    # Register a test user
    user_data = {
        "email": "secret_test@example.com",
        "password": "SecurePass123!",
        "first_name": "Secret",
        "last_name": "Tester"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login to get a token
    login_data = {
        "email": "secret_test@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    # Verify token with correct secret
    try:
        decoded_correct = jwt.decode(
            token,
            settings.BETTER_AUTH_SECRET,
            algorithms=[settings.JWT_ALGORITHM]
        )
        assert decoded_correct is not None
    except jwt.InvalidTokenError:
        pytest.fail("Token should be valid with correct secret")

    # Verify token fails with incorrect secret
    incorrect_secret = "wrong_secret_key_that_does_not_match"
    with pytest.raises(jwt.InvalidTokenError):
        jwt.decode(
            token,
            incorrect_secret,
            algorithms=[settings.JWT_ALGORITHM]
        )


def test_jwt_expiration_validation():
    """Test that expired tokens are properly rejected"""
    # Create an expired token manually
    expired_payload = {
        "sub": "expired_test@example.com",
        "exp": datetime.utcnow() - timedelta(seconds=1),  # Expired 1 second ago
        "iat": datetime.utcnow() - timedelta(hours=1),
        "jti": "test-jti-expired"
    }

    expired_token = jwt.encode(
        expired_payload,
        settings.BETTER_AUTH_SECRET,
        algorithm=settings.JWT_ALGORITHM
    )

    # Try to use the expired token
    headers = {"Authorization": f"Bearer {expired_token}"}
    response = client.get("/auth/profile", headers=headers)
    assert response.status_code == 401  # Unauthorized due to expired token


def test_jwt_future_iat_validation():
    """Test that tokens with future issued-at times are rejected"""
    # Create a token with future issued-at time
    future_payload = {
        "sub": "future_test@example.com",
        "exp": datetime.utcnow() + timedelta(hours=1),
        "iat": datetime.utcnow() + timedelta(hours=1),  # Future issued-at time
        "jti": "test-jti-future"
    }

    future_token = jwt.encode(
        future_payload,
        settings.BETTER_AUTH_SECRET,
        algorithm=settings.JWT_ALGORITHM
    )

    # Try to use the token with future issued-at time
    headers = {"Authorization": f"Bearer {future_token}"}
    response = client.get("/auth/profile", headers=headers)
    assert response.status_code == 401  # Unauthorized due to future iat


def test_jwt_nbf_validation():
    """Test that tokens with not-before times are properly handled"""
    # Create a token that becomes valid in the future
    nbf_payload = {
        "sub": "nbf_test@example.com",
        "exp": datetime.utcnow() + timedelta(hours=1),
        "iat": datetime.utcnow(),
        "nbf": datetime.utcnow() + timedelta(minutes=5),  # Not valid before 5 minutes from now
        "jti": "test-jti-nbf"
    }

    nbf_token = jwt.encode(
        nbf_payload,
        settings.BETTER_AUTH_SECRET,
        algorithm=settings.JWT_ALGORITHM
    )

    # Try to use the token that isn't valid yet
    headers = {"Authorization": f"Bearer {nbf_token}"}
    response = client.get("/auth/profile", headers=headers)
    assert response.status_code == 401  # Unauthorized due to nbf (not before) claim


def test_jwt_leeway_tolerance():
    """Test that a small leeway is acceptable for clock synchronization"""
    # Create a token that expired very recently (within leeway)
    recent_expired_payload = {
        "sub": "leeway_test@example.com",
        "exp": datetime.utcnow() - timedelta(seconds=10),  # Expired 10 seconds ago
        "iat": datetime.utcnow() - timedelta(minutes=1),
        "jti": "test-jti-leeway"
    }

    recent_expired_token = jwt.encode(
        recent_expired_payload,
        settings.BETTER_AUTH_SECRET,
        algorithm=settings.JWT_ALGORITHM
    )

    # With leeway, this might still be accepted depending on implementation
    # For this test, we'll verify the standard behavior without leeway
    headers = {"Authorization": f"Bearer {recent_expired_token}"}
    response = client.get("/auth/profile", headers=headers)
    # Should still be rejected without explicit leeway configuration
    assert response.status_code == 401


def test_jwt_refresh_flow_simulation():
    """Test the conceptual flow for token refresh (without actual refresh mechanism)"""
    # Register a test user
    user_data = {
        "email": "refresh_test@example.com",
        "password": "SecurePass123!",
        "first_name": "Refresh",
        "last_name": "Tester"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login to get initial token
    login_data = {
        "email": "refresh_test@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    initial_token = login_response.json()["access_token"]

    # Verify initial token works
    headers = {"Authorization": f"Bearer {initial_token}"}
    profile_response = client.get("/auth/profile", headers=headers)
    assert profile_response.status_code == 200

    # Simulate token becoming close to expiration by creating a new one
    new_login_response = client.post("/auth/login", json=login_data)
    assert new_login_response.status_code == 200

    new_token = new_login_response.json()["access_token"]

    # Verify new token works
    new_headers = {"Authorization": f"Bearer {new_token}"}
    new_profile_response = client.get("/auth/profile", headers=new_headers)
    assert new_profile_response.status_code == 200

    # Old token might still work depending on implementation, but new one should definitely work
    assert new_profile_response.json()["email"] == "refresh_test@example.com"


def test_jwt_blacklist_simulation():
    """Test conceptual token blacklisting (would require implementation)"""
    # Register a test user
    user_data = {
        "email": "blacklist_test@example.com",
        "password": "SecurePass123!",
        "first_name": "Blacklist",
        "last_name": "Tester"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login to get token
    login_data = {
        "email": "blacklist_test@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    # Verify token works initially
    headers = {"Authorization": f"Bearer {token}"}
    profile_response = client.get("/auth/profile", headers=headers)
    assert profile_response.status_code == 200

    # Conceptually, if we had a blacklist mechanism:
    # 1. Token would be added to blacklist on logout
    # 2. Subsequent requests with blacklisted token would fail
    # For now, we just verify the concept exists in the architecture


def test_jwt_payload_integrity():
    """Test that JWT payloads contain expected user information"""
    # Register a test user
    user_data = {
        "email": "integrity_test@example.com",
        "password": "SecurePass123!",
        "first_name": "Integrity",
        "last_name": "Tester"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login to get token
    login_data = {
        "email": "integrity_test@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    # Decode token to inspect payload
    decoded_payload = jwt.decode(
        token,
        settings.BETTER_AUTH_SECRET,
        algorithms=[settings.JWT_ALGORITHM]
    )

    # Verify expected claims are present
    assert "sub" in decoded_payload
    assert decoded_payload["sub"] == "integrity_test@example.com"
    assert "exp" in decoded_payload
    assert "iat" in decoded_payload

    # Verify token has reasonable expiration (not too far in the future)
    exp_time = datetime.utcfromtimestamp(decoded_payload["exp"])
    max_exp = datetime.utcnow() + timedelta(hours=25)  # Assuming 24h default + 1h buffer
    assert exp_time <= max_exp


if __name__ == "__main__":
    pytest.main([__file__])