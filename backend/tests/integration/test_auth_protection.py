import pytest
from fastapi.testclient import TestClient
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
        "email": "protectiontest@test.com",
        "username": "protection_test_user",
        "password": "securepassword123",
        "first_name": "Protection",
        "last_name": "Test"
    }

    register_response = client.post("/api/auth/register", json=registration_data)
    assert register_response.status_code == 201

    # Login to get the token
    login_data = {
        "email": "protectiontest@test.com",
        "password": "securepassword123"
    }

    login_response = client.post("/api/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["data"]["token"]
    return token


def test_access_protected_task_endpoints_without_token(client: TestClient):
    """Test that all task endpoints require authentication"""
    endpoints_to_test = [
        ("/api/tasks", "GET"),
        ("/api/tasks", "POST"),
        ("/api/tasks/1", "GET"),
        ("/api/tasks/1", "PUT"),
        ("/api/tasks/1/complete", "PATCH"),
        ("/api/tasks/1", "DELETE")
    ]

    for endpoint, method in endpoints_to_test:
        if method == "GET":
            response = client.get(endpoint)
        elif method == "POST":
            response = client.post(endpoint, json={})
        elif method == "PUT":
            response = client.put(endpoint, json={})
        elif method == "PATCH":
            response = client.patch(endpoint)
        elif method == "DELETE":
            response = client.delete(endpoint)

        # All should return 401 (Unauthorized) without authentication
        assert response.status_code == 401, f"Endpoint {endpoint} with method {method} should require authentication"

        data = response.json()
        assert "detail" in data


def test_access_protected_task_endpoints_with_invalid_token(client: TestClient):
    """Test that all task endpoints reject invalid tokens"""
    endpoints_to_test = [
        ("/api/tasks", "GET"),
        ("/api/tasks", "POST"),
        ("/api/tasks/1", "GET"),
        ("/api/tasks/1", "PUT"),
        ("/api/tasks/1/complete", "PATCH"),
        ("/api/tasks/1", "DELETE")
    ]

    for endpoint, method in endpoints_to_test:
        headers = {"Authorization": "Bearer invalid_token_here"}

        if method == "GET":
            response = client.get(endpoint, headers=headers)
        elif method == "POST":
            response = client.post(endpoint, json={}, headers=headers)
        elif method == "PUT":
            response = client.put(endpoint, json={}, headers=headers)
        elif method == "PATCH":
            response = client.patch(endpoint, headers=headers)
        elif method == "DELETE":
            response = client.delete(endpoint, headers=headers)

        # All should return 401 (Unauthorized) with invalid token
        assert response.status_code == 401, f"Endpoint {endpoint} with method {method} should reject invalid tokens"

        data = response.json()
        assert "detail" in data


def test_cross_user_task_access_protection(client: TestClient):
    """Test that users cannot access tasks belonging to other users"""
    # Create first user and get token
    user1_data = {
        "email": "user1@test.com",
        "username": "user1_test",
        "password": "securepassword123",
        "first_name": "User",
        "last_name": "One"
    }

    register_response1 = client.post("/api/auth/register", json=user1_data)
    assert register_response1.status_code == 201

    login_response1 = client.post("/api/auth/login", json={"email": "user1@test.com", "password": "securepassword123"})
    assert login_response1.status_code == 200
    token1 = login_response1.json()["data"]["token"]

    # Create second user and get token
    user2_data = {
        "email": "user2@test.com",
        "username": "user2_test",
        "password": "securepassword123",
        "first_name": "User",
        "last_name": "Two"
    }

    register_response2 = client.post("/api/auth/register", json=user2_data)
    assert register_response2.status_code == 201

    login_response2 = client.post("/api/auth/login", json={"email": "user2@test.com", "password": "securepassword123"})
    assert login_response2.status_code == 200
    token2 = login_response2.json()["data"]["token"]

    # User 1 creates a task
    task_data = {
        "title": "User 1's Private Task",
        "description": "This task belongs to user 1",
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                 json=task_data,
                                 headers={"Authorization": f"Bearer {token1}"})
    assert create_response.status_code == 201
    task_id = create_response.json()["data"]["id"]

    # User 2 should not be able to access user 1's task
    access_response = client.get(f"/api/tasks/{task_id}",
                                headers={"Authorization": f"Bearer {token2}"})
    # Should return 404 (Not Found) or 403 (Forbidden) to prevent user enumeration
    assert access_response.status_code in [403, 404], f"User 2 should not be able to access User 1's task"

    # User 1 should still be able to access their own task
    own_access_response = client.get(f"/api/tasks/{task_id}",
                                    headers={"Authorization": f"Bearer {token1}"})
    assert own_access_response.status_code == 200, f"User 1 should be able to access their own task"


def test_cross_user_task_modification_protection(client: TestClient):
    """Test that users cannot modify tasks belonging to other users"""
    # Create first user and get token
    user1_data = {
        "email": "modifyuser1@test.com",
        "username": "modify_user1",
        "password": "securepassword123",
        "first_name": "Modify",
        "last_name": "User1"
    }

    register_response1 = client.post("/api/auth/register", json=user1_data)
    assert register_response1.status_code == 201

    login_response1 = client.post("/api/auth/login", json={"email": "modifyuser1@test.com", "password": "securepassword123"})
    assert login_response1.status_code == 200
    token1 = login_response1.json()["data"]["token"]

    # Create second user and get token
    user2_data = {
        "email": "modifyuser2@test.com",
        "username": "modify_user2",
        "password": "securepassword123",
        "first_name": "Modify",
        "last_name": "User2"
    }

    register_response2 = client.post("/api/auth/register", json=user2_data)
    assert register_response2.status_code == 201

    login_response2 = client.post("/api/auth/login", json={"email": "modifyuser2@test.com", "password": "securepassword123"})
    assert login_response2.status_code == 200
    token2 = login_response2.json()["data"]["token"]

    # User 1 creates a task
    task_data = {
        "title": "User 1's Private Task",
        "description": "This task belongs to user 1",
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                 json=task_data,
                                 headers={"Authorization": f"Bearer {token1}"})
    assert create_response.status_code == 201
    task_id = create_response.json()["data"]["id"]

    # User 2 should not be able to update user 1's task
    update_data = {
        "title": "Hacked by User 2",
        "completed": True
    }

    update_response = client.put(f"/api/tasks/{task_id}",
                                json=update_data,
                                headers={"Authorization": f"Bearer {token2}"})
    assert update_response.status_code in [403, 404], f"User 2 should not be able to update User 1's task"

    # User 2 should not be able to delete user 1's task
    delete_response = client.delete(f"/api/tasks/{task_id}",
                                   headers={"Authorization": f"Bearer {token2}"})
    assert delete_response.status_code in [403, 404], f"User 2 should not be able to delete User 1's task"

    # User 2 should not be able to toggle completion of user 1's task
    toggle_response = client.patch(f"/api/tasks/{task_id}/complete",
                                  headers={"Authorization": f"Bearer {token2}"})
    assert toggle_response.status_code in [403, 404], f"User 2 should not be able to toggle completion of User 1's task"

    # Verify user 1 can still access their task (unchanged)
    verify_response = client.get(f"/api/tasks/{task_id}",
                                headers={"Authorization": f"Bearer {token1}"})
    assert verify_response.status_code == 200
    task_data = verify_response.json()["data"]
    assert task_data["title"] == "User 1's Private Task"  # Title should not have changed
    assert task_data["completed"] is False  # Completion should not have changed


def test_protected_profile_endpoint_access(client: TestClient):
    """Test that the profile endpoint requires authentication"""
    # Try to access profile without token
    response_no_auth = client.get("/api/auth/profile")
    assert response_no_auth.status_code == 401

    # Register and login to get a token
    registration_data = {
        "email": "profiletest@test.com",
        "username": "profile_test_user",
        "password": "securepassword123",
        "first_name": "Profile",
        "last_name": "Test"
    }

    register_response = client.post("/api/auth/register", json=registration_data)
    assert register_response.status_code == 201

    login_data = {
        "email": "profiletest@test.com",
        "password": "securepassword123"
    }

    login_response = client.post("/api/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["data"]["token"]

    # Access profile with valid token
    response_with_auth = client.get("/api/auth/profile",
                                   headers={"Authorization": f"Bearer {token}"})
    assert response_with_auth.status_code == 200


def test_multiple_auth_headers_handling(client: TestClient):
    """Test handling of requests with multiple Authorization headers"""
    # Register and login to get a token
    registration_data = {
        "email": "multiauthtest@test.com",
        "username": "multi_auth_test_user",
        "password": "securepassword123",
        "first_name": "Multi",
        "last_name": "Auth"
    }

    register_response = client.post("/api/auth/register", json=registration_data)
    assert register_response.status_code == 201

    login_data = {
        "email": "multiauthtest@test.com",
        "password": "securepassword123"
    }

    login_response = client.post("/api/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["data"]["token"]

    # Try to access protected endpoint with multiple auth headers (should handle gracefully)
    # This is difficult to test directly with TestClient, so we'll test malformed headers
    response = client.get("/api/auth/profile",
                         headers={
                            "Authorization": f"Bearer {token}",
                            "X-Extra-Auth": f"Bearer {token}"  # Extra header with auth-like content
                         })
    # Should still work with the valid header
    assert response.status_code in [200, 401]  # Either works or rejects the extra header appropriately


def test_auth_header_format_variations(client: TestClient):
    """Test handling of various Authorization header formats"""
    # Register and login to get a token
    registration_data = {
        "email": "authtest@test.com",
        "username": "auth_test_user",
        "password": "securepassword123",
        "first_name": "Auth",
        "last_name": "Format"
    }

    register_response = client.post("/api/auth/register", json=registration_data)
    assert register_response.status_code == 201

    login_data = {
        "email": "authtest@test.com",
        "password": "securepassword123"
    }

    login_response = client.post("/api/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["data"]["token"]

    # Test with lowercase bearer
    response_lowercase = client.get("/api/auth/profile",
                                   headers={"Authorization": f"bearer {token}"})
    assert response_lowercase.status_code in [401, 200]  # May be rejected or accepted depending on implementation

    # Test with no space between Bearer and token
    response_no_space = client.get("/api/auth/profile",
                                  headers={"Authorization": f"Bearer{token}"})
    assert response_no_space.status_code == 401  # Should be rejected

    # Test with empty auth header
    response_empty = client.get("/api/auth/profile",
                               headers={"Authorization": ""})
    assert response_empty.status_code == 401

    # Test with just "Bearer " and no token
    response_just_bearer = client.get("/api/auth/profile",
                                     headers={"Authorization": "Bearer "})
    assert response_just_bearer.status_code == 401


def test_protected_routes_return_consistent_error_format(client: TestClient):
    """Test that all protected routes return consistent error responses"""
    # Try to access a protected route without authentication
    response = client.get("/api/tasks")

    assert response.status_code == 401
    data = response.json()

    # Check for consistent error format
    assert "detail" in data
    assert isinstance(data["detail"], str)


def test_auth_logging_verification(client: TestClient):
    """Test that authentication failures are properly logged (verification through behavior)"""
    # Try to access protected endpoint with invalid token
    response = client.get("/api/tasks", headers={"Authorization": "Bearer definitely_not_a_valid_token"})

    # Should return 401 with appropriate error message
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data
    assert "credentials" in data["detail"] or "token" in data["detail"]


if __name__ == "__main__":
    pytest.main()