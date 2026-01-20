"""
CORS Configuration and Cross-Origin Request Handling Tests

This module tests that CORS is properly configured to allow legitimate cross-origin
requests while preventing unauthorized access.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.main import app
from sqlmodel import SQLModel
from src.database.engine import get_session
from src.config import settings


# Create test database engine
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_cors.db"
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


def test_cors_allow_credentials_header_present(setup_test_database):
    """Test that Access-Control-Allow-Credentials header is properly set"""
    # Register a user
    user_data = {
        "email": "cors_creds_test@example.com",
        "password": "SecurePass123!",
        "first_name": "CORS",
        "last_name": "Credentials"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login to get a token
    login_data = {
        "email": "cors_creds_test@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Make a request to an authenticated endpoint
    response = client.get("/auth/profile", headers=headers)

    # Check that CORS credentials header is present and set to true
    assert "access-control-allow-credentials" in response.headers
    assert response.headers["access-control-allow-credentials"] == "true"


def test_cors_allow_methods_header(setup_test_database):
    """Test that Access-Control-Allow-Methods header is properly set"""
    # Make a preflight request (OPTIONS) to test CORS methods
    response = client.options(
        "/auth/profile",
        headers={
            "Origin": "http://localhost:3000",  # Typical frontend origin
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization,content-type"
        }
    )

    # Check that allowed methods are properly set
    assert "access-control-allow-methods" in response.headers
    allowed_methods = response.headers["access-control-allow-methods"]

    # Should include common HTTP methods
    assert "GET" in allowed_methods
    assert "POST" in allowed_methods
    assert "PUT" in allowed_methods
    assert "DELETE" in allowed_methods
    assert "PATCH" in allowed_methods


def test_cors_allow_headers_header(setup_test_database):
    """Test that Access-Control-Allow-Headers header is properly set"""
    # Make a preflight request to test allowed headers
    response = client.options(
        "/auth/profile",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization,content-type,x-custom-header"
        }
    )

    # Check that allowed headers are properly set
    assert "access-control-allow-headers" in response.headers
    allowed_headers = response.headers["access-control-allow-headers"]

    # Should include common headers
    assert "authorization" in allowed_headers.lower()
    assert "content-type" in allowed_headers.lower()


def test_cors_allow_origin_matching(setup_test_database):
    """Test that CORS allows configured origins"""
    # Register a user
    user_data = {
        "email": "cors_origin_test@example.com",
        "password": "SecurePass123!",
        "first_name": "CORS",
        "last_name": "Origin"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login to get a token
    login_data = {
        "email": "cors_origin_test@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Make a request with a legitimate origin
    response = client.get(
        "/auth/profile",
        headers={**headers, "Origin": "http://localhost:3000"}
    )

    # Check that the origin is allowed
    assert "access-control-allow-origin" in response.headers
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_cors_disallow_unsafe_origins(setup_test_database):
    """Test that CORS configuration doesn't allow unsafe origins"""
    # Register a user
    user_data = {
        "email": "cors_unsafe_test@example.com",
        "password": "SecurePass123!",
        "first_name": "CORS",
        "last_name": "Unsafe"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login to get a token
    login_data = {
        "email": "cors_unsafe_test@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Make a request with a potentially unsafe origin
    response = client.get(
        "/auth/profile",
        headers={**headers, "Origin": "http://malicious-site.com"}
    )

    # For security, the response should not include the malicious origin in the allow header
    # The exact behavior depends on CORS configuration - could be 400 or the header might not be set
    # If the header is set, it should not match the unsafe origin
    if "access-control-allow-origin" in response.headers:
        assert response.headers["access-control-allow-origin"] != "http://malicious-site.com"


def test_cors_preflight_request_handling(setup_test_database):
    """Test proper handling of CORS preflight requests"""
    # Make a preflight request
    response = client.options(
        "/auth/register",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,authorization"
        }
    )

    # Preflight should return 200 (or 204) for valid requests
    assert response.status_code in [200, 204]

    # Check essential CORS headers in preflight response
    assert "access-control-allow-origin" in response.headers
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"

    assert "access-control-allow-methods" in response.headers
    assert "POST" in response.headers["access-control-allow-methods"]

    assert "access-control-allow-headers" in response.headers
    assert "content-type" in response.headers["access-control-allow-headers"].lower()


def test_cors_with_actual_request(setup_test_database):
    """Test CORS headers with actual requests (not preflight)"""
    # Register a user with a request that includes Origin header
    user_data = {
        "email": "cors_actual_test@example.com",
        "password": "SecurePass123!",
        "first_name": "CORS",
        "last_name": "Actual"
    }

    response = client.post(
        "/auth/register",
        json=user_data,
        headers={"Origin": "http://localhost:3000"}
    )

    assert response.status_code == 200

    # Check that CORS headers are included in the actual response
    assert "access-control-allow-origin" in response.headers
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_cors_various_http_methods(setup_test_database):
    """Test CORS configuration with various HTTP methods"""
    # Register and login to get a token
    user_data = {
        "email": "cors_methods_test@example.com",
        "password": "SecurePass123!",
        "first_name": "CORS",
        "last_name": "Methods"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    login_data = {
        "email": "cors_methods_test@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}", "Origin": "http://localhost:3000"}

    # Test GET request
    get_response = client.get("/auth/profile", headers=headers)
    assert get_response.status_code == 200
    assert "access-control-allow-origin" in get_response.headers

    # Create a task for PUT and DELETE tests
    task_data = {
        "title": "CORS Test Task",
        "description": "Task for CORS testing",
        "completed": False
    }

    create_response = client.post("/tasks/", json=task_data, headers=headers)
    assert create_response.status_code == 200
    task_id = create_response.json()["id"]

    # Test PUT request
    update_data = {
        "title": "Updated CORS Test Task",
        "description": "Updated task for CORS testing",
        "completed": True
    }

    put_response = client.put(f"/tasks/{task_id}", json=update_data, headers=headers)
    assert put_response.status_code == 200
    assert "access-control-allow-origin" in put_response.headers

    # Test DELETE request
    delete_response = client.delete(f"/tasks/{task_id}", headers=headers)
    assert delete_response.status_code == 200
    assert "access-control-allow-origin" in delete_response.headers


def test_cors_wildcard_configuration_security(setup_test_database):
    """Test that CORS is not configured with wildcard when credentials are allowed"""
    # In a properly secured app, when credentials are allowed,
    # the origin cannot be wildcard (*)
    # This test verifies the security constraint

    # Register and login
    user_data = {
        "email": "cors_wildcard_test@example.com",
        "password": "SecurePass123!",
        "first_name": "CORS",
        "last_name": "Wildcard"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    login_data = {
        "email": "cors_wildcard_test@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}", "Origin": "http://localhost:3000"}

    # Make request
    response = client.get("/auth/profile", headers=headers)

    # Verify that if credentials are allowed, origin is not wildcard
    if response.headers.get("access-control-allow-credentials") == "true":
        # The origin should be specific, not wildcard
        allowed_origin = response.headers.get("access-control-allow-origin")
        assert allowed_origin != "*"  # Should not be wildcard when credentials are allowed


def test_cors_multiple_allowed_origins(setup_test_database):
    """Test CORS with multiple allowed origins"""
    # Register and login
    user_data = {
        "email": "cors_multi_origin_test@example.com",
        "password": "SecurePass123!",
        "first_name": "CORS",
        "last_name": "MultiOrigin"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    login_data = {
        "email": "cors_multi_origin_test@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Test with different allowed origins
    allowed_origins = [
        "http://localhost:3000",
        "http://localhost:3001",
        "https://myapp.com",
        "https://www.myapp.com"
    ]

    for origin in allowed_origins:
        response = client.get(
            "/auth/profile",
            headers={**headers, "Origin": origin}
        )

        # Should allow the origin
        if "access-control-allow-origin" in response.headers:
            # The response should either allow this specific origin
            assert response.headers["access-control-allow-origin"] == origin


def test_cors_non_browser_requests(setup_test_database):
    """Test that CORS doesn't interfere with non-browser requests"""
    # Register user
    user_data = {
        "email": "cors_non_browser_test@example.com",
        "password": "SecurePass123!",
        "first_name": "CORS",
        "last_name": "NonBrowser"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login without origin header (simulating server-to-server request)
    login_data = {
        "email": "cors_non_browser_test@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Make request without Origin header
    response = client.get("/auth/profile", headers=headers)

    # Should still work normally
    assert response.status_code == 200
    profile_data = response.json()
    assert profile_data["email"] == "cors_non_browser_test@example.com"


if __name__ == "__main__":
    pytest.main([__file__])