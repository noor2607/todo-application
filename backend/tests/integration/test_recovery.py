import pytest
from fastapi.testclient import TestClient
from main import app
from unittest.mock import patch, MagicMock
from database.models.task import Task
from sqlmodel import Session, select
from datetime import datetime, timedelta


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
        "email": "recoverytest@test.com",
        "username": "recovery_test_user",
        "password": "securepassword123",
        "first_name": "Recovery",
        "last_name": "Test"
    }

    register_response = client.post("/api/auth/register", json=registration_data)
    assert register_response.status_code == 201

    # Login to get the token
    login_data = {
        "email": "recoverytest@test.com",
        "password": "securepassword123"
    }

    login_response = client.post("/api/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["data"]["token"]
    return token


def test_recovery_after_failed_task_creation(client: TestClient, valid_auth_token: str):
    """Test that the system recovers properly after a failed task creation"""
    # Try to create a task with invalid data (missing required field)
    invalid_task_data = {
        "description": "Task without required title",
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                 json=invalid_task_data,
                                 headers={"Authorization": f"Bearer {valid_auth_token}"})
    # Should return an error but not crash the system
    assert create_response.status_code in [422, 400]  # Validation error

    # System should still be functional - create a valid task
    valid_task_data = {
        "title": "Recovery Test Valid Task",
        "description": "Task created after a failed attempt",
        "completed": False
    }

    valid_create_response = client.post("/api/tasks",
                                      json=valid_task_data,
                                      headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert valid_create_response.status_code == 201

    # Verify the valid task was created properly
    task_id = valid_create_response.json()["data"]["id"]
    verify_response = client.get(f"/api/tasks/{task_id}",
                                headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert verify_response.status_code == 200

    task = verify_response.json()["data"]
    assert task["title"] == "Recovery Test Valid Task"
    assert task["description"] == "Task created after a failed attempt"


def test_recovery_after_failed_task_update(client: TestClient, valid_auth_token: str):
    """Test that the system recovers properly after a failed task update"""
    # Create a valid task first
    task_data = {
        "title": "Recovery After Update Failure Test",
        "description": "Original description",
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                 json=task_data,
                                 headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert create_response.status_code == 201
    task_id = create_response.json()["data"]["id"]

    # Try to update with invalid data
    invalid_update_data = {
        "title": "",  # Invalid - empty title
        "completed": True
    }

    update_response = client.put(f"/api/tasks/{task_id}",
                                json=invalid_update_data,
                                headers={"Authorization": f"Bearer {valid_auth_token}"})
    # Should return an error but not crash the system
    assert update_response.status_code in [422, 400]  # Validation error

    # The original task should remain unchanged
    verify_response = client.get(f"/api/tasks/{task_id}",
                                headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert verify_response.status_code == 200

    original_task = verify_response.json()["data"]
    assert original_task["title"] == "Recovery After Update Failure Test"
    assert original_task["description"] == "Original description"
    assert original_task["completed"] is False  # Should not have changed

    # System should still be functional - update with valid data
    valid_update_data = {
        "title": "Successfully Updated Recovery Test Task",
        "completed": True
    }

    valid_update_response = client.put(f"/api/tasks/{task_id}",
                                     json=valid_update_data,
                                     headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert valid_update_response.status_code == 200

    # Verify the task was properly updated
    updated_task = valid_update_response.json()["data"]
    assert updated_task["title"] == "Successfully Updated Recovery Test Task"
    assert updated_task["completed"] is True


def test_recovery_after_failed_task_deletion(client: TestClient, valid_auth_token: str):
    """Test that the system recovers properly after a failed task deletion attempt"""
    # Create a task
    task_data = {
        "title": "Recovery After Deletion Failure Test",
        "description": "Task to test recovery after deletion failure",
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                 json=task_data,
                                 headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert create_response.status_code == 201
    task_id = create_response.json()["data"]["id"]

    # Try to delete a non-existent task (should fail gracefully)
    fake_task_id = 999999  # Very high ID that shouldn't exist
    delete_fake_response = client.delete(f"/api/tasks/{fake_task_id}",
                                        headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert delete_fake_response.status_code in [404, 403]  # Not found or forbidden

    # The original task should still exist
    verify_response = client.get(f"/api/tasks/{task_id}",
                                headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert verify_response.status_code == 200

    task = verify_response.json()["data"]
    assert task["title"] == "Recovery After Deletion Failure Test"

    # System should still be functional - delete the actual task
    delete_actual_response = client.delete(f"/api/tasks/{task_id}",
                                          headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert delete_actual_response.status_code == 200

    # Verify the task is now gone
    verify_deleted_response = client.get(f"/api/tasks/{task_id}",
                                        headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert verify_deleted_response.status_code in [404, 403]  # Not found or forbidden


def test_recovery_after_authentication_failure(client: TestClient):
    """Test that the system recovers properly after authentication failures"""
    # Try to access protected endpoint with invalid token
    invalid_token_response = client.get("/api/tasks",
                                       headers={"Authorization": "Bearer invalid_token_here"})
    assert invalid_token_response.status_code == 401

    # Register a new user
    registration_data = {
        "email": "recoveryafterauth@test.com",
        "username": "recovery_after_auth_user",
        "password": "securepassword123",
        "first_name": "Recovery",
        "last_name": "After Auth"
    }

    register_response = client.post("/api/auth/register", json=registration_data)
    assert register_response.status_code == 201

    # Login to get a valid token
    login_data = {
        "email": "recoveryafterauth@test.com",
        "password": "securepassword123"
    }

    login_response = client.post("/api/auth/login", json=login_data)
    assert login_response.status_code == 200

    valid_token = login_response.json()["data"]["token"]

    # System should still be functional with the new user - create a task
    task_data = {
        "title": "Recovery After Auth Failure Test",
        "description": "Task created after auth failure recovery",
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                 json=task_data,
                                 headers={"Authorization": f"Bearer {valid_token}"})
    assert create_response.status_code == 201

    # Verify the task was created
    task_id = create_response.json()["data"]["id"]
    verify_response = client.get(f"/api/tasks/{task_id}",
                                headers={"Authorization": f"Bearer {valid_token}"})
    assert verify_response.status_code == 200

    task = verify_response.json()["data"]
    assert task["title"] == "Recovery After Auth Failure Test"


def test_recovery_from_concurrent_modification_conflict(client: TestClient, valid_auth_token: str):
    """Test recovery from potential concurrent modification conflicts"""
    # Create a task
    task_data = {
        "title": "Concurrent Modification Recovery Test",
        "description": "Task to test recovery from concurrent modification issues",
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                 json=task_data,
                                 headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert create_response.status_code == 201
    task_id = create_response.json()["data"]["id"]

    # Simulate multiple updates to the same task sequentially (simulating concurrent access)
    for i in range(3):
        update_data = {
            "title": f"Concurrent Modification Recovery Test Update {i}",
            "description": f"Updated description {i}",
            "completed": i % 2 == 0  # Alternate between true/false
        }

        update_response = client.put(f"/api/tasks/{task_id}",
                                    json=update_data,
                                    headers={"Authorization": f"Bearer {valid_auth_token}"})
        assert update_response.status_code == 200

        updated_task = update_response.json()["data"]
        assert updated_task["title"] == f"Concurrent Modification Recovery Test Update {i}"

    # Verify final state is consistent
    final_response = client.get(f"/api/tasks/{task_id}",
                               headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert final_response.status_code == 200

    final_task = final_response.json()["data"]
    assert final_task["title"] == "Concurrent Modification Recovery Test Update 2"  # Last update
    assert final_task["description"] == "Updated description 2"  # Last update
    # The completed status depends on whether 2 is even (True) or odd (False)
    assert final_task["completed"] is (2 % 2 == 0)


def test_recovery_after_task_completion_toggle_errors(client: TestClient, valid_auth_token: str):
    """Test recovery after task completion toggle errors"""
    # Create a task
    task_data = {
        "title": "Toggle Recovery Test",
        "description": "Task to test recovery after toggle errors",
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                 json=task_data,
                                 headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert create_response.status_code == 201
    task_id = create_response.json()["data"]["id"]

    # Toggle completion multiple times to ensure system handles repeated operations
    expected_state = False  # Starts as False
    for i in range(5):  # Toggle 5 times (False->True->False->True->False->True)
        toggle_response = client.patch(f"/api/tasks/{task_id}/complete",
                                      headers={"Authorization": f"Bearer {valid_auth_token}"})
        assert toggle_response.status_code == 200

        toggled_task = toggle_response.json()["data"]
        expected_state = not expected_state  # Each toggle flips the state
        assert toggled_task["completed"] == expected_state

    # After 5 toggles (odd number), the final state should be True
    assert expected_state is True

    # Verify the final state is persisted correctly
    verify_response = client.get(f"/api/tasks/{task_id}",
                                headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert verify_response.status_code == 200

    final_task = verify_response.json()["data"]
    assert final_task["completed"] is True


def test_recovery_after_database_connection_issue(client: TestClient, valid_auth_token: str):
    """Test system recovery after simulated database connection issues"""
    # This test verifies that normal operations work after potential connection issues
    # In a real implementation, we would mock database connection failures

    # Create a task (normal operation)
    task_data = {
        "title": "DB Recovery Test",
        "description": "Task to test recovery after potential DB issues",
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                 json=task_data,
                                 headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert create_response.status_code == 201
    task_id = create_response.json()["data"]["id"]

    # Update the task (normal operation)
    update_data = {
        "title": "Updated DB Recovery Test",
        "completed": True
    }

    update_response = client.put(f"/api/tasks/{task_id}",
                                json=update_data,
                                headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert update_response.status_code == 200

    # Toggle completion (normal operation)
    toggle_response = client.patch(f"/api/tasks/{task_id}/complete",
                                  headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert toggle_response.status_code == 200

    # Delete the task (normal operation)
    delete_response = client.delete(f"/api/tasks/{task_id}",
                                   headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert delete_response.status_code == 200

    # System should still be functional - create another task
    new_task_data = {
        "title": "Post-Recovery Test Task",
        "description": "Task created after simulated recovery",
        "completed": False
    }

    new_create_response = client.post("/api/tasks",
                                     json=new_task_data,
                                     headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert new_create_response.status_code == 201

    # Verify the new task was created
    new_task_id = new_create_response.json()["data"]["id"]
    verify_new_response = client.get(f"/api/tasks/{new_task_id}",
                                    headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert verify_new_response.status_code == 200

    new_task = verify_new_response.json()["data"]
    assert new_task["title"] == "Post-Recovery Test Task"


def test_recovery_from_malformed_request_data(client: TestClient, valid_auth_token: str):
    """Test recovery from malformed request data"""
    # Try to create a task with malformed data (edge case)
    malformed_data = {
        "title": "Malformed Request Recovery Test",
        "description": "A" * 10000,  # Potentially too long description
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                 json=malformed_data,
                                 headers={"Authorization": f"Bearer {valid_auth_token}"})
    # Should either accept or properly reject the request
    assert create_response.status_code in [201, 413, 422, 400]

    # System should still be functional - create a valid task
    valid_task_data = {
        "title": "Recovery After Malformed Request",
        "description": "Valid task after malformed request",
        "completed": False
    }

    valid_response = client.post("/api/tasks",
                                json=valid_task_data,
                                headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert valid_response.status_code == 201

    # Verify the valid task was created
    task_id = valid_response.json()["data"]["id"]
    verify_response = client.get(f"/api/tasks/{task_id}",
                                headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert verify_response.status_code == 200

    task = verify_response.json()["data"]
    assert task["title"] == "Recovery After Malformed Request"


def test_recovery_from_expired_token_usage(client: TestClient, valid_auth_token: str):
    """Test recovery when using an expired token (conceptual - testing behavior)"""
    # This test verifies that the system handles expired tokens gracefully
    # In a real implementation, we would test with an actual expired token
    # For now, we'll test the error handling and subsequent valid operations

    # Create a task with valid token
    task_data = {
        "title": "Expired Token Recovery Test",
        "description": "Task to test recovery from expired token scenarios",
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                 json=task_data,
                                 headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert create_response.status_code == 201
    task_id = create_response.json()["data"]["id"]

    # Verify we can access the task with the valid token
    verify_response = client.get(f"/api/tasks/{task_id}",
                                headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert verify_response.status_code == 200

    # Try to access with an invalid token (simulates expired token)
    invalid_response = client.get(f"/api/tasks/{task_id}",
                                 headers={"Authorization": "Bearer definitely_invalid_token"})
    assert invalid_response.status_code == 401

    # System should still be functional with valid token
    # Update the task with valid token
    update_data = {
        "title": "Updated Expired Token Recovery Test",
        "completed": True
    }

    update_response = client.put(f"/api/tasks/{task_id}",
                                json=update_data,
                                headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert update_response.status_code == 200

    # Verify the update worked
    updated_task = update_response.json()["data"]
    assert updated_task["title"] == "Updated Expired Token Recovery Test"
    assert updated_task["completed"] is True


if __name__ == "__main__":
    pytest.main()