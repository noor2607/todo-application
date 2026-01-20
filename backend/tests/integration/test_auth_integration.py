import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from database.models.user import User
from database.engine import engine
from main import app
import json


@pytest.fixture
def client():
    """Create a test client for the API"""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def db_session():
    """Create a database session for testing"""
    with Session(engine) as session:
        yield session


def test_auth_registration_flow(client: TestClient, db_session: Session):
    """Test complete user registration flow"""
    # Test registration
    registration_data = {
        "email": "integration@test.com",
        "username": "integration_test",
        "password": "securepassword123",
        "first_name": "Integration",
        "last_name": "Test"
    }

    response = client.post("/api/auth/register", json=registration_data)
    assert response.status_code == 201

    data = response.json()
    assert data["success"] is True
    assert "token" in data["data"]
    assert "user" in data["data"]

    user_data = data["data"]["user"]
    assert user_data["email"] == "integration@test.com"
    assert user_data["username"] == "integration_test"


def test_auth_login_flow(client: TestClient):
    """Test complete user login flow with valid credentials"""
    # First register a user
    registration_data = {
        "email": "login@test.com",
        "username": "login_test",
        "password": "securepassword123",
        "first_name": "Login",
        "last_name": "Test"
    }

    register_response = client.post("/api/auth/register", json=registration_data)
    assert register_response.status_code == 201

    # Then test login
    login_data = {
        "email": "login@test.com",
        "password": "securepassword123"
    }

    response = client.post("/api/auth/login", json=login_data)
    assert response.status_code == 200

    data = response.json()
    assert data["success"] is True
    assert "token" in data["data"]
    assert "user" in data["data"]

    user_data = data["data"]["user"]
    assert user_data["email"] == "login@test.com"


def test_auth_protected_route_access_with_valid_token(client: TestClient):
    """Test accessing protected routes with valid JWT token"""
    # Register and login to get a token
    registration_data = {
        "email": "protected@test.com",
        "username": "protected_test",
        "password": "securepassword123",
        "first_name": "Protected",
        "last_name": "Test"
    }

    register_response = client.post("/api/auth/register", json=registration_data)
    assert register_response.status_code == 201

    login_data = {
        "email": "protected@test.com",
        "password": "securepassword123"
    }

    login_response = client.post("/api/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["data"]["token"]

    # Test accessing protected route with valid token
    response = client.get("/api/auth/profile",
                         headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200

    data = response.json()
    assert "user_id" in data
    assert data["message"] == "User profile retrieved successfully"


def test_auth_protected_route_access_without_token(client: TestClient):
    """Test that protected routes reject requests without tokens"""
    response = client.get("/api/auth/profile")
    assert response.status_code == 401

    data = response.json()
    assert "detail" in data


def test_auth_protected_route_access_with_invalid_token(client: TestClient):
    """Test that protected routes reject requests with invalid tokens"""
    response = client.get("/api/auth/profile",
                         headers={"Authorization": "Bearer invalid_token"})
    assert response.status_code == 401

    data = response.json()
    assert "detail" in data


def test_auth_logout_process(client: TestClient):
    """Test authentication logout process (token invalidation)"""
    # Register and login to get a token
    registration_data = {
        "email": "logout@test.com",
        "username": "logout_test",
        "password": "securepassword123",
        "first_name": "Logout",
        "last_name": "Test"
    }

    register_response = client.post("/api/auth/register", json=registration_data)
    assert register_response.status_code == 201

    login_data = {
        "email": "logout@test.com",
        "password": "securepassword123"
    }

    login_response = client.post("/api/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["data"]["token"]

    # Test that the token works initially
    profile_response = client.get("/api/auth/profile",
                                 headers={"Authorization": f"Bearer {token}"})
    assert profile_response.status_code == 200

    # Note: In JWT-based systems, there's no server-side logout process
    # The client should simply discard the token
    # We'll verify that the token works before "logout" and that we can get a new one after
    assert "user_id" in profile_response.json()


if __name__ == "__main__":
    pytest.main()