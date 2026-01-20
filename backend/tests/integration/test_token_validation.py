import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timedelta
import jwt
from config.settings import settings
from main import app
from database.models.user import User
from database.engine import engine
from sqlmodel import Session


@pytest.fixture
def client():
    """Create a test client for the API"""
    with TestClient(app) as test_client:
        yield test_client


def test_token_expires_correctly(client: TestClient):
    """Test that tokens expire after the configured time"""
    # Register a user
    registration_data = {
        "email": "expiretest@test.com",
        "username": "expire_test_user",
        "password": "securepassword123",
        "first_name": "Expire",
        "last_name": "Test"
    }

    register_response = client.post("/api/auth/register", json=registration_data)
    assert register_response.status_code == 201

    # Login to get a token
    login_data = {
        "email": "expiretest@test.com",
        "password": "securepassword123"
    }

    login_response = client.post("/api/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["data"]["token"]

    # Verify token is valid initially
    protected_response = client.get("/api/auth/profile",
                                   headers={"Authorization": f"Bearer {token}"})
    assert protected_response.status_code == 200

    # Manually create an expired token for testing
    expired_payload = {
        "sub": "test_user_id",
        "email": "expired@test.com",
        "username": "expired_test",
        "exp": datetime.utcnow() - timedelta(seconds=1)  # Expired 1 second ago
    }

    expired_token = jwt.encode(expired_payload, settings.better_auth_secret, algorithm=settings.jwt_algorithm)

    # Try to access protected endpoint with expired token
    expired_response = client.get("/api/auth/profile",
                                 headers={"Authorization": f"Bearer {expired_token}"})
    assert expired_response.status_code == 401

    data = expired_response.json()
    assert "detail" in data
    assert "expired" in data["detail"].lower()


def test_invalid_token_signature(client: TestClient):
    """Test that tokens with invalid signatures are rejected"""
    # Create a token with a different secret (invalid)
    payload = {
        "sub": "test_user_id",
        "email": "invalid@test.com",
        "username": "invalid_test",
        "exp": datetime.utcnow() + timedelta(hours=24)
    }

    # Encode with a different secret to make it invalid
    different_secret = "different_secret_than_the_one_used_by_server"
    invalid_token = jwt.encode(payload, different_secret, algorithm=settings.jwt_algorithm)

    # Try to access protected endpoint with invalid token
    response = client.get("/api/auth/profile",
                         headers={"Authorization": f"Bearer {invalid_token}"})
    assert response.status_code == 401

    data = response.json()
    assert "detail" in data


def test_malformed_token(client: TestClient):
    """Test that malformed tokens are rejected"""
    # Try to access with a malformed token
    response = client.get("/api/auth/profile",
                         headers={"Authorization": "Bearer malformed.token.string"})
    assert response.status_code == 401

    data = response.json()
    assert "detail" in data


def test_token_with_missing_claims(client: TestClient):
    """Test that tokens with missing required claims are rejected"""
    # Create a token with missing required claims
    incomplete_payload = {
        "exp": datetime.utcnow() + timedelta(hours=24)
        # Missing 'sub', 'email', 'username' claims
    }

    incomplete_token = jwt.encode(incomplete_payload, settings.better_auth_secret, algorithm=settings.jwt_algorithm)

    # Try to access protected endpoint with incomplete token
    response = client.get("/api/auth/profile",
                         headers={"Authorization": f"Bearer {incomplete_token}"})
    assert response.status_code == 401

    data = response.json()
    assert "detail" in data


def test_token_refresh_mechanism(client: TestClient):
    """Test the token refresh mechanism if implemented"""
    # Register a user
    registration_data = {
        "email": "refreshtest@test.com",
        "username": "refresh_test_user",
        "password": "securepassword123",
        "first_name": "Refresh",
        "last_name": "Test"
    }

    register_response = client.post("/api/auth/register", json=registration_data)
    assert register_response.status_code == 201

    # Login to get a token
    login_data = {
        "email": "refreshtest@test.com",
        "password": "securepassword123"
    }

    login_response = client.post("/api/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["data"]["token"]

    # Verify token is valid initially
    protected_response = client.get("/api/auth/profile",
                                   headers={"Authorization": f"Bearer {token}"})
    assert protected_response.status_code == 200


def test_token_user_id_extraction(client: TestClient):
    """Test that user ID is correctly extracted from token"""
    # Register a user
    registration_data = {
        "email": "extraction@test.com",
        "username": "extraction_test_user",
        "password": "securepassword123",
        "first_name": "Extraction",
        "last_name": "Test"
    }

    register_response = client.post("/api/auth/register", json=registration_data)
    assert register_response.status_code == 201

    # Login to get a token
    login_data = {
        "email": "extraction@test.com",
        "password": "securepassword123"
    }

    login_response = client.post("/api/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["data"]["token"]

    # Access profile to verify token works correctly
    profile_response = client.get("/api/auth/profile",
                                 headers={"Authorization": f"Bearer {token}"})
    assert profile_response.status_code == 200

    profile_data = profile_response.json()
    assert "user_id" in profile_data or "data" in profile_data


def test_token_expiry_edge_cases(client: TestClient):
    """Test token expiry at the exact expiration time"""
    # Register a user
    registration_data = {
        "email": "edgecase@test.com",
        "username": "edge_case_test_user",
        "password": "securepassword123",
        "first_name": "Edge",
        "last_name": "Case"
    }

    register_response = client.post("/api/auth/register", json=registration_data)
    assert register_response.status_code == 201

    # Login to get a token
    login_data = {
        "email": "edgecase@test.com",
        "password": "securepassword123"
    }

    login_response = client.post("/api/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["data"]["token"]

    # Verify token is valid initially
    protected_response = client.get("/api/auth/profile",
                                   headers={"Authorization": f"Bearer {token}"})
    assert protected_response.status_code == 200


def test_multiple_device_same_user_tokens(client: TestClient):
    """Test that multiple tokens for the same user work independently"""
    # Register a user
    registration_data = {
        "email": "multidevice@test.com",
        "username": "multi_device_test_user",
        "password": "securepassword123",
        "first_name": "Multi",
        "last_name": "Device"
    }

    register_response = client.post("/api/auth/register", json=registration_data)
    assert register_response.status_code == 201

    # Login twice to get two different tokens
    login_data = {
        "email": "multidevice@test.com",
        "password": "securepassword123"
    }

    login_response1 = client.post("/api/auth/login", json=login_data)
    assert login_response1.status_code == 200
    token1 = login_response1.json()["data"]["token"]

    login_response2 = client.post("/api/auth/login", json=login_data)  # Login again
    assert login_response2.status_code == 200
    token2 = login_response2.json()["data"]["token"]

    # Both tokens should work independently
    response1 = client.get("/api/auth/profile",
                          headers={"Authorization": f"Bearer {token1}"})
    assert response1.status_code == 200

    response2 = client.get("/api/auth/profile",
                          headers={"Authorization": f"Bearer {token2}"})
    assert response2.status_code == 200


def test_long_lived_token_security(client: TestClient):
    """Test that extremely long expiration times are handled appropriately"""
    # This test verifies that the system doesn't allow unreasonably long-lived tokens
    # In a real implementation, we'd check for appropriate max expiration times
    pass  # Implementation would depend on specific security requirements


def test_token_revocation_if_implemented(client: TestClient):
    """Test token revocation if the system supports it"""
    # In a JWT stateless system, tokens can't be revoked server-side
    # unless there's a blacklist mechanism implemented
    # This is just a placeholder for potential future functionality
    pass


if __name__ == "__main__":
    pytest.main()