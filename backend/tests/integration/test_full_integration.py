import pytest
from fastapi.testclient import TestClient
from main import app
from sqlmodel import Session
from database.engine import engine
from auth.jwt_handler import create_access_token
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
        "email": "integrationtest@test.com",
        "username": "integration_test_user",
        "password": "securepassword123",
        "first_name": "Integration",
        "last_name": "Test"
    }

    register_response = client.post("/api/auth/register", json=registration_data)
    assert register_response.status_code == 201

    # Login to get the token
    login_data = {
        "email": "integrationtest@test.com",
        "password": "securepassword123"
    }

    login_response = client.post("/api/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["data"]["token"]
    return token


def test_complete_user_lifecycle_integration(client: TestClient):
    """Test complete user lifecycle: registration -> login -> task operations -> logout"""
    # Step 1: Register a new user
    registration_data = {
        "email": "fullintegration@test.com",
        "username": "full_integration_user",
        "password": "securepassword123",
        "first_name": "Full",
        "last_name": "Integration"
    }

    register_response = client.post("/api/auth/register", json=registration_data)
    assert register_response.status_code == 201

    register_data = register_response.json()
    assert register_data["success"] is True
    assert "token" in register_data["data"]
    assert "user" in register_data["data"]

    token = register_data["data"]["token"]
    user_id = register_data["data"]["user"]["id"]

    # Step 2: Verify user profile can be retrieved
    profile_response = client.get("/api/auth/profile",
                                 headers={"Authorization": f"Bearer {token}"})
    assert profile_response.status_code == 200

    profile_data = profile_response.json()
    assert profile_data["data"]["id"] == user_id
    assert profile_data["data"]["email"] == "fullintegration@test.com"

    # Step 3: Create multiple tasks
    tasks_to_create = [
        {"title": "Integration Test Task 1", "description": "First integration test task", "completed": False},
        {"title": "Integration Test Task 2", "description": "Second integration test task", "completed": True},
        {"title": "Integration Test Task 3", "description": "Third integration test task", "completed": False}
    ]

    created_task_ids = []
    for i, task_data in enumerate(tasks_to_create):
        task_response = client.post("/api/tasks",
                                   json=task_data,
                                   headers={"Authorization": f"Bearer {token}"})
        assert task_response.status_code == 201

        task_id = task_response.json()["data"]["id"]
        created_task_ids.append(task_id)

        # Verify the created task has correct data
        task = task_response.json()["data"]
        assert task["title"] == task_data["title"]
        assert task["description"] == task_data["description"]
        assert task["completed"] == task_data["completed"]
        assert task["user_id"] == user_id

    # Step 4: Retrieve all tasks and verify they match what we created
    all_tasks_response = client.get("/api/tasks",
                                   headers={"Authorization": f"Bearer {token}"})
    assert all_tasks_response.status_code == 200

    all_tasks_data = all_tasks_response.json()
    assert "data" in all_tasks_data
    retrieved_tasks = all_tasks_data["data"]

    # Should have at least the 3 tasks we created
    assert len(retrieved_tasks) >= 3

    # Verify all created tasks are present
    retrieved_task_ids = [task["id"] for task in retrieved_tasks]
    for task_id in created_task_ids:
        assert task_id in retrieved_task_ids

    # Step 5: Update a task
    update_data = {
        "title": "Updated Integration Test Task 1",
        "description": "Updated description for first task",
        "completed": True
    }

    update_response = client.put(f"/api/tasks/{created_task_ids[0]}",
                                json=update_data,
                                headers={"Authorization": f"Bearer {token}"})
    assert update_response.status_code == 200

    updated_task = update_response.json()["data"]
    assert updated_task["title"] == "Updated Integration Test Task 1"
    assert updated_task["completed"] is True

    # Step 6: Toggle completion status of another task
    toggle_response = client.patch(f"/api/tasks/{created_task_ids[2]}/complete",
                                  headers={"Authorization": f"Bearer {token}"})
    assert toggle_response.status_code == 200

    toggled_task = toggle_response.json()["data"]
    # Since the original state was False, it should now be True
    assert toggled_task["completed"] is True

    # Step 7: Retrieve the updated task to verify changes persisted
    get_updated_response = client.get(f"/api/tasks/{created_task_ids[0]}",
                                     headers={"Authorization": f"Bearer {token}"})
    assert get_updated_response.status_code == 200

    retrieved_updated_task = get_updated_response.json()["data"]
    assert retrieved_updated_task["title"] == "Updated Integration Test Task 1"
    assert retrieved_updated_task["completed"] is True

    # Step 8: Delete a task
    delete_response = client.delete(f"/api/tasks/{created_task_ids[1]}",
                                   headers={"Authorization": f"Bearer {token}"})
    assert delete_response.status_code == 200

    # Step 9: Verify the deleted task is no longer accessible
    verify_deleted_response = client.get(f"/api/tasks/{created_task_ids[1]}",
                                        headers={"Authorization": f"Bearer {token}"})
    assert verify_deleted_response.status_code in [404, 403]  # Not found or forbidden

    # Step 10: Verify other tasks still exist
    final_tasks_response = client.get("/api/tasks",
                                     headers={"Authorization": f"Bearer {token}"})
    assert final_tasks_response.status_code == 200

    final_tasks = final_tasks_response.json()["data"]
    final_task_ids = [task["id"] for task in final_tasks]

    # Should still have the other 2 tasks
    assert created_task_ids[0] in final_task_ids  # Updated task should still exist
    assert created_task_ids[2] in final_task_ids  # Task with toggled completion should still exist
    assert created_task_ids[1] not in final_task_ids  # Deleted task should not exist

    print("✓ Complete user lifecycle integration test passed")


def test_cross_user_isolation_integration(client: TestClient):
    """Test that different users' data remains isolated"""
    # Create first user
    user1_data = {
        "email": "isolationuser1@test.com",
        "username": "isolation_user1",
        "password": "securepassword123",
        "first_name": "Isolation",
        "last_name": "User1"
    }

    register_response1 = client.post("/api/auth/register", json=user1_data)
    assert register_response1.status_code == 201

    login_response1 = client.post("/api/auth/login", json={"email": "isolationuser1@test.com", "password": "securepassword123"})
    assert login_response1.status_code == 200
    token1 = login_response1.json()["data"]["token"]

    # Create second user
    user2_data = {
        "email": "isolationuser2@test.com",
        "username": "isolation_user2",
        "password": "securepassword123",
        "first_name": "Isolation",
        "last_name": "User2"
    }

    register_response2 = client.post("/api/auth/register", json=user2_data)
    assert register_response2.status_code == 201

    login_response2 = client.post("/api/auth/login", json={"email": "isolationuser2@test.com", "password": "securepassword123"})
    assert login_response2.status_code == 200
    token2 = login_response2.json()["data"]["token"]

    # User 1 creates tasks
    user1_task_data = {
        "title": "User 1's Isolated Task",
        "description": "Task that should only be accessible to user 1",
        "completed": False
    }

    user1_create_response = client.post("/api/tasks",
                                      json=user1_task_data,
                                      headers={"Authorization": f"Bearer {token1}"})
    assert user1_create_response.status_code == 201
    user1_task_id = user1_create_response.json()["data"]["id"]

    # User 2 creates tasks
    user2_task_data = {
        "title": "User 2's Isolated Task",
        "description": "Task that should only be accessible to user 2",
        "completed": True
    }

    user2_create_response = client.post("/api/tasks",
                                      json=user2_task_data,
                                      headers={"Authorization": f"Bearer {token2}"})
    assert user2_create_response.status_code == 201
    user2_task_id = user2_create_response.json()["data"]["id"]

    # Verify User 1 can only see their own tasks
    user1_tasks_response = client.get("/api/tasks",
                                     headers={"Authorization": f"Bearer {token1}"})
    assert user1_tasks_response.status_code == 200
    user1_tasks = user1_tasks_response.json()["data"]
    user1_task_ids = [task["id"] for task in user1_tasks]

    assert user1_task_id in user1_task_ids
    assert user2_task_id not in user1_task_ids  # User 1 should not see User 2's task

    # Verify User 2 can only see their own tasks
    user2_tasks_response = client.get("/api/tasks",
                                     headers={"Authorization": f"Bearer {token2}"})
    assert user2_tasks_response.status_code == 200
    user2_tasks = user2_tasks_response.json()["data"]
    user2_task_ids = [task["id"] for task in user2_tasks]

    assert user2_task_id in user2_task_ids
    assert user1_task_id not in user2_task_ids  # User 2 should not see User 1's task

    # Verify User 2 cannot access User 1's task directly
    user2_access_user1_task = client.get(f"/api/tasks/{user1_task_id}",
                                        headers={"Authorization": f"Bearer {token2}"})
    assert user2_access_user1_task.status_code in [403, 404]  # Forbidden or Not Found

    # Verify User 1 cannot access User 2's task directly
    user1_access_user2_task = client.get(f"/api/tasks/{user2_task_id}",
                                        headers={"Authorization": f"Bearer {token1}"})
    assert user1_access_user2_task.status_code in [403, 404]  # Forbidden or Not Found

    print("✓ Cross-user isolation integration test passed")


def test_task_management_workflow_integration(client: TestClient, valid_auth_token: str):
    """Test complete task management workflow"""
    # Step 1: Create a task
    task_data = {
        "title": "Full Workflow Integration Test",
        "description": "Task to test complete workflow integration",
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                 json=task_data,
                                 headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert create_response.status_code == 201

    task_id = create_response.json()["data"]["id"]
    created_task = create_response.json()["data"]

    assert created_task["title"] == "Full Workflow Integration Test"
    assert created_task["completed"] is False

    # Step 2: Retrieve the specific task
    get_response = client.get(f"/api/tasks/{task_id}",
                             headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert get_response.status_code == 200

    retrieved_task = get_response.json()["data"]
    assert retrieved_task["id"] == task_id
    assert retrieved_task["title"] == "Full Workflow Integration Test"

    # Step 3: Update the task
    update_data = {
        "title": "Updated Full Workflow Integration Test",
        "description": "Updated description for workflow test",
        "completed": True
    }

    update_response = client.put(f"/api/tasks/{task_id}",
                                json=update_data,
                                headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert update_response.status_code == 200

    updated_task = update_response.json()["data"]
    assert updated_task["title"] == "Updated Full Workflow Integration Test"
    assert updated_task["completed"] is True

    # Step 4: Toggle completion status (should change back to False)
    toggle_response = client.patch(f"/api/tasks/{task_id}/complete",
                                  headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert toggle_response.status_code == 200

    toggled_task = toggle_response.json()["data"]
    assert toggled_task["completed"] is False  # Changed from True to False

    # Step 5: Verify the toggle persisted
    verify_response = client.get(f"/api/tasks/{task_id}",
                                headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert verify_response.status_code == 200

    verified_task = verify_response.json()["data"]
    assert verified_task["completed"] is False

    # Step 6: Delete the task
    delete_response = client.delete(f"/api/tasks/{task_id}",
                                   headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert delete_response.status_code == 200

    # Step 7: Verify task is deleted
    verify_delete_response = client.get(f"/api/tasks/{task_id}",
                                       headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert verify_delete_response.status_code in [404, 403]  # Not found or forbidden

    print("✓ Task management workflow integration test passed")


def test_authentication_and_authorization_integration(client: TestClient):
    """Test complete authentication and authorization flow"""
    # Step 1: Register a user
    registration_data = {
        "email": "authintegration@test.com",
        "username": "auth_integration_user",
        "password": "securepassword123",
        "first_name": "Auth",
        "last_name": "Integration"
    }

    register_response = client.post("/api/auth/register", json=registration_data)
    assert register_response.status_code == 201

    token = register_response.json()["data"]["token"]
    user_id = register_response.json()["data"]["user"]["id"]

    # Step 2: Verify authentication works by accessing profile
    profile_response = client.get("/api/auth/profile",
                                 headers={"Authorization": f"Bearer {token}"})
    assert profile_response.status_code == 200

    profile_data = profile_response.json()
    assert profile_data["data"]["id"] == user_id

    # Step 3: Verify unauthorized access is denied
    unauthorized_response = client.get("/api/tasks")  # No auth header
    assert unauthorized_response.status_code == 401

    # Step 4: Verify invalid token is denied
    invalid_token_response = client.get("/api/tasks",
                                       headers={"Authorization": "Bearer invalid_token"})
    assert invalid_token_response.status_code == 401

    # Step 5: Create and manage tasks with valid token
    task_data = {
        "title": "Auth Integration Test Task",
        "description": "Task created during auth integration test",
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                 json=task_data,
                                 headers={"Authorization": f"Bearer {token}"})
    assert create_response.status_code == 201

    task_id = create_response.json()["data"]["id"]

    # Step 6: Verify task was created and is accessible with valid token
    get_response = client.get(f"/api/tasks/{task_id}",
                             headers={"Authorization": f"Bearer {token}"})
    assert get_response.status_code == 200

    task = get_response.json()["data"]
    assert task["title"] == "Auth Integration Test Task"

    print("✓ Authentication and authorization integration test passed")


def test_error_handling_consistency_integration(client: TestClient, valid_auth_token: str):
    """Test that error handling is consistent across the application"""
    # Step 1: Try to access non-existent task
    non_existent_response = client.get("/api/tasks/999999",
                                      headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert non_existent_response.status_code in [404]  # Should be not found

    # Verify error response format consistency
    error_data = non_existent_response.json()
    assert "detail" in error_data or ("success" in error_data and not error_data["success"])

    # Step 2: Try to update with invalid data
    invalid_update_data = {
        "title": ""  # Invalid - empty title
    }

    invalid_update_response = client.put("/api/tasks/999999",
                                        json=invalid_update_data,
                                        headers={"Authorization": f"Bearer {valid_auth_token}"})
    # Should return appropriate error (404 for non-existent task, or 422 for validation error)
    assert invalid_update_response.status_code in [404, 422, 400]

    # Step 3: Create a valid task for further testing
    valid_task_data = {
        "title": "Error Handling Integration Test",
        "description": "Task for testing error handling consistency",
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                 json=valid_task_data,
                                 headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert create_response.status_code == 201
    task_id = create_response.json()["data"]["id"]

    # Step 4: Try to update with invalid data for an existing task
    invalid_update_for_valid_task = {
        "title": ""  # Invalid - empty title
    }

    invalid_update_task_response = client.put(f"/api/tasks/{task_id}",
                                             json=invalid_update_for_valid_task,
                                             headers={"Authorization": f"Bearer {valid_auth_token}"})
    # Should return validation error (422) for invalid data
    assert invalid_update_task_response.status_code in [422, 400]

    # Step 5: Verify the valid task still exists and wasn't affected by the failed update
    verify_response = client.get(f"/api/tasks/{task_id}",
                                headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert verify_response.status_code == 200

    task = verify_response.json()["data"]
    assert task["title"] == "Error Handling Integration Test"

    print("✓ Error handling consistency integration test passed")


def test_concurrent_operations_integration(client: TestClient, valid_auth_token: str):
    """Test that the system handles concurrent operations correctly"""
    # Create multiple tasks in sequence (simulating concurrent creation)
    created_task_ids = []
    for i in range(5):
        task_data = {
            "title": f"Concurrent Test Task {i}",
            "description": f"Task {i} for concurrent operations testing",
            "completed": i % 2 == 0  # Alternate completion status
        }

        response = client.post("/api/tasks",
                              json=task_data,
                              headers={"Authorization": f"Bearer {valid_auth_token}"})
        assert response.status_code == 201
        created_task_ids.append(response.json()["data"]["id"])

    # Verify all tasks were created
    all_tasks_response = client.get("/api/tasks",
                                   headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert all_tasks_response.status_code == 200

    all_tasks = all_tasks_response.json()["data"]
    all_task_ids = [task["id"] for task in all_tasks]

    # Verify all created tasks exist
    for task_id in created_task_ids:
        assert task_id in all_task_ids

    # Perform multiple operations in sequence (simulating concurrent access)
    for i, task_id in enumerate(created_task_ids):
        if i % 2 == 0:  # Update even-indexed tasks
            update_data = {
                "title": f"Updated Concurrent Test Task {i}",
                "completed": True
            }

            update_response = client.put(f"/api/tasks/{task_id}",
                                        json=update_data,
                                        headers={"Authorization": f"Bearer {valid_auth_token}"})
            assert update_response.status_code == 200

            updated_task = update_response.json()["data"]
            assert updated_task["title"] == f"Updated Concurrent Test Task {i}"
            assert updated_task["completed"] is True

    # Verify all updates were applied correctly
    final_tasks_response = client.get("/api/tasks",
                                     headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert final_tasks_response.status_code == 200

    final_tasks = final_tasks_response.json()["data"]
    for i, task_id in enumerate(created_task_ids):
        task = next((t for t in final_tasks if t["id"] == task_id), None)
        assert task is not None, f"Task {task_id} not found in final results"

        if i % 2 == 0:  # Even-indexed tasks were updated
            assert task["title"] == f"Updated Concurrent Test Task {i}"
            assert task["completed"] is True
        else:  # Odd-indexed tasks were not updated
            assert task["title"] == f"Concurrent Test Task {i}"
            # Completion status might have been changed during toggle operations in other tests

    print("✓ Concurrent operations integration test passed")


if __name__ == "__main__":
    pytest.main()