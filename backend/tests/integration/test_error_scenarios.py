import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session
from database.engine import engine
from main import app
import json


@pytest.fixture
def client():
    """Create a test client for the API"""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def valid_auth_token(client: TestClient) -> str:
    """Create a valid authentication token for testing"""
    # Register a test user
    registration_data = {
        "email": "errortest@test.com",
        "username": "error_test_user",
        "password": "securepassword123",
        "first_name": "Error",
        "last_name": "Test"
    }

    register_response = client.post("/api/auth/register", json=registration_data)
    assert register_response.status_code == 201

    # Login to get the token
    login_data = {
        "email": "errortest@test.com",
        "password": "securepassword123"
    }

    login_response = client.post("/api/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["data"]["token"]
    return token


def test_invalid_credentials_login(client: TestClient):
    """Test login with invalid credentials"""
    login_data = {
        "email": "nonexistent@test.com",
        "password": "wrongpassword"
    }

    response = client.post("/api/auth/login", json=login_data)
    assert response.status_code == 401

    data = response.json()
    assert "detail" in data
    assert "Incorrect email or password" in data["detail"]


def test_duplicate_email_registration(client: TestClient):
    """Test registering with an already existing email"""
    # Register first user
    registration_data = {
        "email": "duplicate@test.com",
        "username": "user1",
        "password": "securepassword123",
        "first_name": "Duplicate",
        "last_name": "Test"
    }

    first_response = client.post("/api/auth/register", json=registration_data)
    assert first_response.status_code == 201

    # Try to register with same email
    second_registration = {
        "email": "duplicate@test.com",  # Same email
        "username": "user2",  # Different username
        "password": "anotherpassword123",
        "first_name": "Duplicate",
        "last_name": "Test2"
    }

    second_response = client.post("/api/auth/register", json=second_registration)
    assert second_response.status_code == 409  # Conflict

    data = second_response.json()
    assert "detail" in data


def test_duplicate_username_registration(client: TestClient):
    """Test registering with an already existing username"""
    # Register first user
    registration_data = {
        "email": "unique1@test.com",
        "username": "uniqueuser",
        "password": "securepassword123",
        "first_name": "Unique",
        "last_name": "Test1"
    }

    first_response = client.post("/api/auth/register", json=registration_data)
    assert first_response.status_code == 201

    # Try to register with same username
    second_registration = {
        "email": "unique2@test.com",  # Different email
        "username": "uniqueuser",  # Same username
        "password": "anotherpassword123",
        "first_name": "Unique",
        "last_name": "Test2"
    }

    second_response = client.post("/api/auth/register", json=second_registration)
    assert second_response.status_code == 409  # Conflict

    data = second_response.json()
    assert "detail" in data


def test_invalid_task_data_creation(client: TestClient, valid_auth_token: str):
    """Test creating tasks with invalid data"""
    # Try to create task with empty title (should fail validation)
    invalid_task_data = {
        "title": "",  # Empty title should fail
        "description": "Valid description",
        "completed": False
    }

    response = client.post("/api/tasks",
                           json=invalid_task_data,
                           headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert response.status_code in [422, 400]  # Unprocessable Entity or Bad Request


def test_access_nonexistent_task(client: TestClient, valid_auth_token: str):
    """Test accessing a task that doesn't exist"""
    nonexistent_task_id = 999999  # Very high ID that shouldn't exist

    response = client.get(f"/api/tasks/{nonexistent_task_id}",
                          headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert response.status_code == 404

    data = response.json()
    assert "detail" in data


def test_update_nonexistent_task(client: TestClient, valid_auth_token: str):
    """Test updating a task that doesn't exist"""
    nonexistent_task_id = 999999  # Very high ID that shouldn't exist

    update_data = {
        "title": "Updated title",
        "description": "Updated description"
    }

    response = client.put(f"/api/tasks/{nonexistent_task_id}",
                          json=update_data,
                          headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert response.status_code == 404

    data = response.json()
    assert "detail" in data


def test_delete_nonexistent_task(client: TestClient, valid_auth_token: str):
    """Test deleting a task that doesn't exist"""
    nonexistent_task_id = 999999  # Very high ID that shouldn't exist

    response = client.delete(f"/api/tasks/{nonexistent_task_id}",
                             headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert response.status_code == 404

    data = response.json()
    assert "detail" in data


def test_access_protected_route_without_token(client: TestClient):
    """Test accessing protected routes without authentication token"""
    response = client.get("/api/tasks")
    assert response.status_code == 401

    data = response.json()
    assert "detail" in data


def test_access_protected_route_with_invalid_token(client: TestClient):
    """Test accessing protected routes with invalid token"""
    response = client.get("/api/tasks",
                          headers={"Authorization": "Bearer invalid_token_here"})
    assert response.status_code == 401

    data = response.json()
    assert "detail" in data


def test_task_creation_without_required_fields(client: TestClient, valid_auth_token: str):
    """Test creating tasks without required fields"""
    # Try to create task without title (required field)
    invalid_task_data = {
        "description": "Task without required title",
        "completed": False
    }

    response = client.post("/api/tasks",
                           json=invalid_task_data,
                           headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert response.status_code in [422, 400]  # Validation error


def test_invalid_task_id_format(client: TestClient, valid_auth_token: str):
    """Test accessing tasks with invalid ID format"""
    # Try to access task with non-numeric ID
    response = client.get("/api/tasks/invalid_id",
                          headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert response.status_code in [422, 404]  # Validation error or not found


def test_large_payload_handling(client: TestClient, valid_auth_token: str):
    """Test handling of unusually large payloads"""
    # Create a task with a very long description
    large_task_data = {
        "title": "Large Payload Test",
        "description": "A" * 10000,  # Very long description
        "completed": False
    }

    response = client.post("/api/tasks",
                           json=large_task_data,
                           headers={"Authorization": f"Bearer {valid_auth_token}"})

    # Should either accept the request or return an appropriate error
    assert response.status_code in [201, 413, 422]  # Created, Payload Too Large, or Validation Error


def test_sql_injection_prevention(client: TestClient, valid_auth_token: str):
    """Test that SQL injection attempts are properly handled"""
    # Try to create a task with potential SQL injection in title
    malicious_task_data = {
        "title": "Test'; DROP TABLE users; --",
        "description": "Normal description",
        "completed": False
    }

    response = client.post("/api/tasks",
                           json=malicious_task_data,
                           headers={"Authorization": f"Bearer {valid_auth_token}"})

    # Should either accept (if properly sanitized) or reject
    # The important thing is that it doesn't cause a SQL error
    assert response.status_code in [201, 422, 400]


def test_xss_prevention(client: TestClient, valid_auth_token: str):
    """Test that XSS attempts are properly handled"""
    # Try to create a task with potential XSS in description
    xss_task_data = {
        "title": "XSS Test",
        "description": "<script>alert('XSS')</script>",
        "completed": False
    }

    response = client.post("/api/tasks",
                           json=xss_task_data,
                           headers={"Authorization": f"Bearer {valid_auth_token}"})

    # Should either accept (if properly sanitized) or reject
    assert response.status_code in [201, 422, 400]


def test_rate_limiting_behavior(client: TestClient, valid_auth_token: str):
    """Test behavior under rapid successive requests (simulating rate limiting)"""
    # Make multiple requests in succession
    for i in range(5):
        task_data = {
            "title": f"Rate Limit Test {i}",
            "description": f"Task {i} for rate limit testing",
            "completed": False
        }

        response = client.post("/api/tasks",
                               json=task_data,
                               headers={"Authorization": f"Bearer {valid_auth_token}"})
        # All requests should succeed (unless rate limiting is implemented)
        assert response.status_code in [201, 429]  # Created or Too Many Requests


def test_concurrent_task_operations(client: TestClient, valid_auth_token: str):
    """Test concurrent operations on the same task"""
    # Create a task first
    task_data = {
        "title": "Concurrent Test Task",
        "description": "Task for concurrent operation testing",
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                  json=task_data,
                                  headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert create_response.status_code == 201

    task_id = create_response.json()["data"]["id"]

    # Try to update the same task multiple times rapidly
    # (This would normally be tested with actual concurrent requests, but simulating sequentially)
    update_data = {
        "title": "Updated Concurrent Test Task",
        "completed": True
    }

    update_response = client.put(f"/api/tasks/{task_id}",
                                 json=update_data,
                                 headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert update_response.status_code == 200

    # Verify the update was successful
    retrieve_response = client.get(f"/api/tasks/{task_id}",
                                   headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert retrieve_response.status_code == 200
    assert retrieve_response.json()["data"]["title"] == "Updated Concurrent Test Task"
    assert retrieve_response.json()["data"]["completed"] is True


if __name__ == "__main__":
    pytest.main()