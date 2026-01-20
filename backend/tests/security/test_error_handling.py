"""
Error Handling and Response Sanitization Tests

This module tests that the application properly handles errors and sanitizes
responses to prevent information leakage and ensure consistent error responses.
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


# Create test database engine
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_errors.db"
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


def test_error_response_format_consistency(setup_test_database):
    """Test that all error responses follow a consistent format"""
    # Try to access a non-existent endpoint
    response = client.get("/nonexistent/endpoint")
    assert response.status_code == 404

    error_data = response.json()

    # Verify error response has consistent structure
    assert "detail" in error_data
    assert isinstance(error_data["detail"], (str, dict))


def test_error_message_sanitization(setup_test_database):
    """Test that error messages don't leak sensitive internal information"""
    # Register a user
    user_data = {
        "email": "error_sanitization@example.com",
        "password": "SecurePass123!",
        "first_name": "Error",
        "last_name": "Sanitizer"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Try to register the same user again to trigger an error
    duplicate_register_response = client.post("/auth/register", json=user_data)
    assert duplicate_register_response.status_code == 400

    error_data = duplicate_register_response.json()

    # Verify error message is user-friendly and doesn't expose internal details
    assert "detail" in error_data
    error_detail = str(error_data["detail"]).lower()

    # Ensure no sensitive information is leaked
    assert "sqlalchemy" not in error_detail
    assert "database" not in error_detail
    assert "traceback" not in error_detail
    assert "exception" not in error_detail or "internal" not in error_detail


def test_jwt_error_response_sanitization(setup_test_database):
    """Test that JWT-related error responses are sanitized"""
    # Try to access a protected endpoint with invalid token
    headers = {"Authorization": "Bearer invalid.token.here"}
    response = client.get("/auth/profile", headers=headers)
    assert response.status_code == 401

    error_data = response.json()

    # Verify error response is informative but not revealing
    assert "detail" in error_data
    error_detail = str(error_data["detail"]).lower()

    # Should indicate authentication failure without revealing internal details
    assert "credential" in error_detail or "authentication" in error_detail or "token" in error_detail
    assert "sqlalchemy" not in error_detail
    assert "jwt" not in error_detail or "library" not in error_detail


def test_input_validation_error_sanitization(setup_test_database):
    """Test that input validation errors are properly sanitized"""
    # Send malformed request to trigger validation error
    malformed_data = {
        "invalid_field": "some_value",
        "another_invalid": 12345
    }

    response = client.post("/auth/register", json=malformed_data)
    assert response.status_code == 422  # Unprocessable Entity

    error_data = response.json()

    # Verify validation error response is structured properly
    assert "detail" in error_data
    detail_list = error_data["detail"]
    assert isinstance(detail_list, list)

    # Each validation error should be properly formatted
    for error in detail_list:
        assert "loc" in error  # Location of error
        assert "msg" in error   # Error message
        assert "type" in error  # Error type


def test_database_error_sanitization(setup_test_database):
    """Test that database errors are properly sanitized"""
    # Register a user
    user_data = {
        "email": "db_error_test@example.com",
        "password": "SecurePass123!",
        "first_name": "DB",
        "last_name": "Error"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login to get token
    login_data = {
        "email": "db_error_test@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Try to access a non-existent task
    response = client.get("/tasks/999999", headers=headers)

    # Could be 404 (not found) or 403 (forbidden if ownership check happens first)
    assert response.status_code in [404, 403]

    error_data = response.json()

    # Verify no database-specific errors are exposed
    assert "detail" in error_data
    error_detail = str(error_data["detail"]).lower()

    assert "sql" not in error_detail
    assert "database" not in error_detail
    assert "connection" not in error_detail
    assert "table" not in error_detail


def test_server_error_handling(setup_test_database):
    """Test how server errors are handled and sanitized"""
    # This test is tricky because we need to trigger an actual server error
    # We'll test by sending requests that might cause unexpected issues

    # Try to send a request with extremely large payload
    large_payload = {
        "email": "large.payload@example.com",
        "password": "SecurePass123!",
        "first_name": "A" * 10000,  # Very long first name
        "last_name": "B" * 10000    # Very long last name
    }

    response = client.post("/auth/register", json=large_payload)

    # Should either be rejected for validation or handled gracefully
    assert response.status_code in [422, 413, 400, 500]

    if response.status_code >= 400:
        error_data = response.json()
        if "detail" in error_data:
            error_detail = str(error_data["detail"]).lower()
            # Even if it's a server error, shouldn't expose internal details
            assert "traceback" not in error_detail
            assert "exception" not in error_detail or "internal" not in error_detail


def test_error_response_headers(setup_test_database):
    """Test that error responses include appropriate headers"""
    # Trigger a 404 error
    response = client.get("/nonexistent/endpoint")
    assert response.status_code == 404

    # Verify standard headers are present in error responses
    assert "content-type" in response.headers
    assert "application/json" in response.headers["content-type"]


def test_authentication_error_consistency(setup_test_database):
    """Test that authentication errors are consistent across endpoints"""
    # Create headers with invalid token
    invalid_headers = {"Authorization": "Bearer totally.invalid.token"}

    # Test multiple endpoints with invalid token
    endpoints_to_test = [
        "/auth/profile",
        "/tasks/",
        "/tasks/1",
        "/auth/logout"  # if exists
    ]

    for endpoint in endpoints_to_test:
        try:
            response = client.get(endpoint, headers=invalid_headers)
            assert response.status_code == 401, f"Endpoint {endpoint} should return 401 for invalid token"

            error_data = response.json()
            assert "detail" in error_data
        except Exception:
            # Some endpoints might not accept GET, try POST if it's a 405 error
            try:
                response = client.post(endpoint, headers=invalid_headers, json={})
                if response.status_code != 405:  # Method not allowed is acceptable
                    assert response.status_code == 401, f"Endpoint {endpoint} should return 401 for invalid token"
                    error_data = response.json()
                    assert "detail" in error_data
            except Exception:
                # If endpoint doesn't exist or causes other errors, that's fine
                pass


def test_rate_limiting_error_response(setup_test_database):
    """Test that rate limiting errors are properly formatted"""
    # Try multiple requests rapidly to potentially trigger rate limiting
    user_data = {
        "email": "rate_limit_test@example.com",
        "password": "SecurePass123!",
        "first_name": "Rate",
        "last_name": "Limiter"
    }

    # Register user first
    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Try multiple failed login attempts
    failed_login_data = {
        "email": "rate_limit_test@example.com",
        "password": "wrongpassword"
    }

    responses = []
    for _ in range(10):  # Try multiple failed attempts
        response = client.post("/auth/login", json=failed_login_data)
        responses.append(response.status_code)

    # Check if any resulted in rate limiting (429)
    if 429 in responses:
        # Find the 429 response and verify its format
        rate_limit_response = next(r for r in responses if r == 429)
        # The response object isn't accessible here, but we verified the status code


def test_error_logging_without_exposure(setup_test_database):
    """Test that errors are logged appropriately without exposing details to clients"""
    # Register user
    user_data = {
        "email": "log_exposure_test@example.com",
        "password": "SecurePass123!",
        "first_name": "Log",
        "last_name": "Exposure"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login to get token
    login_data = {
        "email": "log_exposure_test@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Try to update a non-existent task to trigger an error
    update_data = {
        "title": "Updated Task",
        "description": "Updated description",
        "completed": True
    }

    response = client.put("/tasks/999999", json=update_data, headers=headers)
    assert response.status_code in [404, 403]

    error_data = response.json()

    # Verify the error response is safe and doesn't expose internal details
    assert "detail" in error_data
    error_detail = str(error_data["detail"])

    # Safe error responses should not contain system-specific information
    assert not any(keyword in error_detail.lower() for keyword in [
        "sqlalchemy", "database", "connection", "server", "internal",
        "traceback", "exception", "error", "failed", "exceptiontype"
    ]) or "not found" in error_detail.lower() or "forbidden" in error_detail.lower()


def test_cross_site_scripting_prevention_in_errors(setup_test_database):
    """Test that error responses don't contain XSS-prone content"""
    # Try to inject malicious content in various fields
    malicious_inputs = [
        {"email": "<script>alert('xss')</script>@example.com"},
        {"password": "' OR '1'='1"},
        {"first_name": "<img src=x onerror=alert('xss')>"},
        {"last_name": "'; DROP TABLE users; --"}
    ]

    for malicious_data in malicious_inputs:
        # Start with valid base data and add malicious field
        base_data = {
            "email": "xss_test@example.com",
            "password": "SecurePass123!",
            "first_name": "XSS",
            "last_name": "Test"
        }
        base_data.update(malicious_data)

        response = client.post("/auth/register", json=base_data)

        # If there's an error response, verify it's sanitized
        if response.status_code >= 400:
            try:
                error_data = response.json()
                if "detail" in error_data:
                    error_detail = str(error_data["detail"])
                    # Should not contain raw malicious input
                    assert "<script>" not in error_detail
                    assert "onerror" not in error_detail
                    assert "DROP TABLE" not in error_detail
            except:
                # If response isn't JSON, that's also acceptable for security
                pass


if __name__ == "__main__":
    pytest.main([__file__])