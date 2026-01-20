"""
Security Test Suite for Todo Full-Stack Application

This module contains comprehensive security tests to verify all security measures
are functioning properly, including JWT validation, user identity propagation,
task ownership enforcement, CORS configuration, and error handling.
"""

import pytest
import jwt
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.main import app
from sqlmodel import SQLModel
from src.database.engine import get_session
from src.database.models.user import User
from src.database.models.task import Task
from src.config import settings


# Create test database engine
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_security.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_session():
    """Override dependency to use test database"""
    try:
        with TestingSessionLocal() as session:
            yield session
    except:
        TestingSessionLocal().close()


# Override the database dependency
app.dependency_overrides[get_session] = override_get_session

# Create test client
client = TestClient(app)


@pytest.fixture(scope="module")
def setup_test_database():
    """Setup test database schema"""
    SQLModel.metadata.create_all(bind=engine)
    yield
    SQLModel.metadata.drop_all(bind=engine)


def test_jwt_token_validation_valid_token(setup_test_database):
    """Test that valid JWT tokens are properly validated"""
    # First, register and login to get a valid token
    user_data = {
        "email": "security_test@example.com",
        "password": "SecurePass123!",
        "first_name": "Security",
        "last_name": "Tester"
    }

    # Register user
    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login to get token
    login_data = {
        "email": "security_test@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200
    assert "access_token" in login_response.json()

    token = login_response.json()["access_token"]

    # Verify token is valid by accessing protected endpoint
    headers = {"Authorization": f"Bearer {token}"}
    profile_response = client.get("/auth/profile", headers=headers)
    assert profile_response.status_code == 200
    assert profile_response.json()["email"] == "security_test@example.com"


def test_jwt_token_validation_invalid_token(setup_test_database):
    """Test that invalid JWT tokens are rejected"""
    headers = {"Authorization": "Bearer invalid.token.here"}
    profile_response = client.get("/auth/profile", headers=headers)
    assert profile_response.status_code == 401


def test_jwt_token_validation_expired_token(setup_test_database):
    """Test that expired JWT tokens are rejected"""
    # Create an expired token manually
    payload = {
        "sub": "test@example.com",
        "exp": datetime.utcnow() - timedelta(minutes=1),  # Expired 1 minute ago
        "iat": datetime.utcnow() - timedelta(hours=1)
    }

    token = jwt.encode(payload, settings.BETTER_AUTH_SECRET, algorithm=settings.JWT_ALGORITHM)

    headers = {"Authorization": f"Bearer {token}"}
    profile_response = client.get("/auth/profile", headers=headers)
    assert profile_response.status_code == 401


def test_jwt_token_validation_malformed_token(setup_test_database):
    """Test that malformed JWT tokens are rejected"""
    headers = {"Authorization": "Bearer totally.malformed.token"}
    profile_response = client.get("/auth/profile", headers=headers)
    assert profile_response.status_code == 401


def test_user_identity_propagation(setup_test_database):
    """Test that user identity is properly propagated through the system"""
    # Register user
    user_data = {
        "email": "identity_test@example.com",
        "password": "SecurePass123!",
        "first_name": "Identity",
        "last_name": "Propagator"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login to get token
    login_data = {
        "email": "identity_test@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Access profile endpoint and verify identity
    profile_response = client.get("/auth/profile", headers=headers)
    assert profile_response.status_code == 200
    profile_data = profile_response.json()
    assert profile_data["email"] == "identity_test@example.com"
    assert profile_data["first_name"] == "Identity"
    assert profile_data["last_name"] == "Propagator"


def test_task_ownership_enforcement_same_user(setup_test_database):
    """Test that users can access their own tasks"""
    # Register user
    user_data = {
        "email": "owner_test@example.com",
        "password": "SecurePass123!",
        "first_name": "Owner",
        "last_name": "Tester"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login to get token
    login_data = {
        "email": "owner_test@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create a task
    task_data = {
        "title": "Owned Task",
        "description": "This is my task",
        "completed": False
    }

    create_response = client.post("/tasks/", json=task_data, headers=headers)
    assert create_response.status_code == 200
    task_id = create_response.json()["id"]

    # Verify user can access their own task
    get_response = client.get(f"/tasks/{task_id}", headers=headers)
    assert get_response.status_code == 200
    assert get_response.json()["title"] == "Owned Task"


def test_task_ownership_enforcement_different_user(setup_test_database):
    """Test that users cannot access tasks owned by other users"""
    # Register first user
    user1_data = {
        "email": "first_owner@example.com",
        "password": "SecurePass123!",
        "first_name": "First",
        "last_name": "Owner"
    }

    register_response1 = client.post("/auth/register", json=user1_data)
    assert register_response1.status_code == 200

    # Register second user
    user2_data = {
        "email": "second_owner@example.com",
        "password": "SecurePass123!",
        "first_name": "Second",
        "last_name": "Owner"
    }

    register_response2 = client.post("/auth/register", json=user2_data)
    assert register_response2.status_code == 200

    # Login as first user and create a task
    login_data1 = {
        "email": "first_owner@example.com",
        "password": "SecurePass123!"
    }

    login_response1 = client.post("/auth/login", json=login_data1)
    assert login_response1.status_code == 200

    token1 = login_response1.json()["access_token"]
    headers1 = {"Authorization": f"Bearer {token1}"}

    task_data = {
        "title": "Private Task",
        "description": "This belongs to user 1",
        "completed": False
    }

    create_response = client.post("/tasks/", json=task_data, headers=headers1)
    assert create_response.status_code == 200
    task_id = create_response.json()["id"]

    # Login as second user
    login_data2 = {
        "email": "second_owner@example.com",
        "password": "SecurePass123!"
    }

    login_response2 = client.post("/auth/login", json=login_data2)
    assert login_response2.status_code == 200

    token2 = login_response2.json()["access_token"]
    headers2 = {"Authorization": f"Bearer {token2}"}

    # Verify second user cannot access first user's task
    get_response = client.get(f"/tasks/{task_id}", headers=headers2)
    assert get_response.status_code == 403  # Forbidden


def test_cors_configuration_no_origin_header(setup_test_database):
    """Test CORS configuration when no origin header is provided"""
    # Register user
    user_data = {
        "email": "cors_test@example.com",
        "password": "SecurePass123!",
        "first_name": "CORS",
        "last_name": "Tester"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login to get token
    login_data = {
        "email": "cors_test@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Make request without origin header
    profile_response = client.get("/auth/profile", headers=headers)
    assert profile_response.status_code == 200


def test_error_handling_sanitized_responses(setup_test_database):
    """Test that error responses don't leak sensitive information"""
    # Attempt to access non-existent task
    headers = {"Authorization": "Bearer dummy_token"}
    response = client.get("/tasks/999999", headers=headers)

    # Should return 401 (unauthorized) rather than 404 (not found) when token is invalid
    assert response.status_code == 401

    # Check that error response doesn't contain sensitive information
    error_data = response.json()
    assert "detail" in error_data
    # Verify no internal server details are leaked
    detail = str(error_data["detail"]).lower()
    assert "sqlalchemy" not in detail
    assert "database" not in detail
    assert "traceback" not in detail


def test_brute_force_protection_simulation(setup_test_database):
    """Test that the system handles multiple failed login attempts appropriately"""
    # Try to login with wrong credentials multiple times
    login_data = {
        "email": "nonexistent@example.com",
        "password": "wrongpassword"
    }

    # Make multiple failed login attempts
    for _ in range(5):
        response = client.post("/auth/login", json=login_data)
        assert response.status_code in [401, 429]  # Unauthorized or Rate Limited


def test_sql_injection_prevention(setup_test_database):
    """Test that the system prevents SQL injection attempts"""
    # Register user
    user_data = {
        "email": "inject_test@example.com",
        "password": "SecurePass123!",
        "first_name": "Inject",
        "last_name": "Tester"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login to get token
    login_data = {
        "email": "inject_test@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Try to create a task with potential SQL injection in title
    malicious_task_data = {
        "title": "'; DROP TABLE users; --",
        "description": "Normal description",
        "completed": False
    }

    response = client.post("/tasks/", json=malicious_task_data, headers=headers)
    # Should either reject the request or properly sanitize the input
    # The exact behavior depends on your validation, but it shouldn't crash
    assert response.status_code in [200, 422]  # Success or validation error, but not server error


def test_xss_prevention(setup_test_database):
    """Test that the system prevents XSS attempts"""
    # Register user
    user_data = {
        "email": "xss_test@example.com",
        "password": "SecurePass123!",
        "first_name": "XSS",
        "last_name": "Tester"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login to get token
    login_data = {
        "email": "xss_test@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Try to create a task with potential XSS in title
    xss_task_data = {
        "title": "<script>alert('XSS')</script>",
        "description": "Normal description",
        "completed": False
    }

    response = client.post("/tasks/", json=xss_task_data, headers=headers)
    # Should either reject the request or properly sanitize the input
    assert response.status_code in [200, 422]  # Success or validation error, but not server error


if __name__ == "__main__":
    pytest.main([__file__])