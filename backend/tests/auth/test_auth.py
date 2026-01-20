import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from fastapi.testclient import TestClient
from src.main import app
from src.auth.jwt_handler import create_access_token


@pytest.fixture
def client():
    """Create a test client for the API"""
    with TestClient(app) as test_client:
        yield test_client


def test_health_endpoint(client):
    """Test the health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200

    data = response.json()
    assert "status" in data
    assert data["status"] == "ok"
    assert "message" in data
    assert "Todo App service is running" in data["message"]


def test_root_endpoint(client):
    """Test the root endpoint"""
    response = client.get("/")
    assert response.status_code == 200

    data = response.json()
    assert "status" in data
    assert data["status"] == "healthy"
    assert "service" in data
    assert "Todo App Backend" in data["service"]


def test_protected_route_without_token(client):
    """Test accessing a protected route without a token returns 401"""
    response = client.get("/api/auth/test-protected")
    assert response.status_code == 401

    data = response.json()
    assert "detail" in data


def test_protected_route_with_valid_token(client):
    """Test accessing a protected route with a valid token works"""
    # Create a valid token
    token_data = {"sub": "user123", "email": "test@example.com"}
    token = create_access_token(token_data)

    # Make request with valid token
    response = client.get(
        "/api/auth/test-protected",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200

    data = response.json()
    assert "user_id" in data
    assert data["user_id"] == "user123"
    assert "message" in data


def test_verify_authentication_endpoint(client):
    """Test the authentication verification endpoint"""
    # Test without token
    response = client.get("/api/auth/verify")
    assert response.status_code == 401

    # Test with valid token
    token_data = {"sub": "user123", "email": "test@example.com"}
    token = create_access_token(token_data)

    response = client.get(
        "/api/auth/verify",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200

    data = response.json()
    assert "authenticated" in data
    assert data["authenticated"] is True


def test_get_user_profile_endpoint(client):
    """Test the user profile endpoint"""
    # Test without token
    response = client.get("/api/auth/profile")
    assert response.status_code == 401

    # Test with valid token
    token_data = {"sub": "user123", "email": "test@example.com"}
    token = create_access_token(token_data)

    response = client.get(
        "/api/auth/profile",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200

    data = response.json()
    assert "user_id" in data
    assert data["user_id"] == "user123"
    assert "message" in data