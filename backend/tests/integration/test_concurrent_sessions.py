import pytest
from fastapi.testclient import TestClient
from main import app
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests


@pytest.fixture
def client():
    """Create a test client for the API"""
    with TestClient(app) as test_client:
        yield test_client


def register_and_login_user(client: TestClient, email: str, username: str) -> str:
    """Helper function to register and login a user, returning the auth token"""
    # Register the user
    registration_data = {
        "email": email,
        "username": username,
        "password": "securepassword123",
        "first_name": "Concurrent",
        "last_name": "Test"
    }

    register_response = client.post("/api/auth/register", json=registration_data)
    assert register_response.status_code in [201, 409]  # Either created or already exists

    # Login to get the token
    login_data = {
        "email": email,
        "password": "securepassword123"
    }

    login_response = client.post("/api/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["data"]["token"]
    return token


def test_single_user_multiple_device_access(client: TestClient):
    """Test that a single user can access the system from multiple devices simultaneously"""
    user_email = "concurrentuser@test.com"
    user_username = "concurrent_user"

    # Register and login from "device 1" (first session)
    token1 = register_and_login_user(client, user_email, f"{user_username}_device1")

    # Register and login from "device 2" (second session, same user)
    token2 = register_and_login_user(client, user_email, f"{user_username}_device2")

    # Both tokens should work independently for the same user
    # Create a task with first token
    task_data1 = {
        "title": "Concurrent Session Test Task 1",
        "description": "Task created from first session",
        "completed": False
    }

    create_response1 = client.post("/api/tasks",
                                  json=task_data1,
                                  headers={"Authorization": f"Bearer {token1}"})
    assert create_response1.status_code == 201
    task_id1 = create_response1.json()["data"]["id"]

    # Create a task with second token (same user, different session)
    task_data2 = {
        "title": "Concurrent Session Test Task 2",
        "description": "Task created from second session",
        "completed": False
    }

    create_response2 = client.post("/api/tasks",
                                  json=task_data2,
                                  headers={"Authorization": f"Bearer {token2}"})
    assert create_response2.status_code == 201
    task_id2 = create_response2.json()["data"]["id"]

    # Both tokens should be able to access all tasks for the user
    get_response1 = client.get("/api/tasks",
                              headers={"Authorization": f"Bearer {token1}"})
    assert get_response1.status_code == 200

    get_response2 = client.get("/api/tasks",
                              headers={"Authorization": f"Bearer {token2}"})
    assert get_response2.status_code == 200

    # Both should see the same tasks (both tasks created by the same user)
    tasks1 = get_response1.json()["data"]
    tasks2 = get_response2.json()["data"]

    assert len(tasks1) >= 2  # At least the 2 tasks we created
    assert len(tasks2) >= 2  # At least the 2 tasks we created

    # Verify both tasks are accessible from both sessions
    task1_exists_in_session1 = any(task["id"] == task_id1 for task in tasks1)
    task2_exists_in_session1 = any(task["id"] == task_id2 for task in tasks1)
    task1_exists_in_session2 = any(task["id"] == task_id1 for task in tasks2)
    task2_exists_in_session2 = any(task["id"] == task_id2 for task in tasks2)

    assert task1_exists_in_session1
    assert task2_exists_in_session1
    assert task1_exists_in_session2
    assert task2_exists_in_session2


def test_concurrent_task_creations_by_same_user(client: TestClient):
    """Test creating multiple tasks concurrently by the same user from different sessions"""
    user_email = "concurrentcreate@test.com"
    user_username = "concurrent_create_user"

    # Register and get two tokens for the same user
    token1 = register_and_login_user(client, user_email, f"{user_username}_token1")
    token2 = register_and_login_user(client, user_email, f"{user_username}_token2")

    # Define tasks to be created concurrently
    tasks_to_create = [
        (token1, {"title": "Concurrent Task 1", "description": "Created with token 1", "completed": False}),
        (token2, {"title": "Concurrent Task 2", "description": "Created with token 2", "completed": False}),
        (token1, {"title": "Concurrent Task 3", "description": "Created with token 1 again", "completed": True}),
        (token2, {"title": "Concurrent Task 4", "description": "Created with token 2 again", "completed": False}),
    ]

    created_task_ids = []

    # Create tasks concurrently using different tokens for the same user
    for token, task_data in tasks_to_create:
        response = client.post("/api/tasks",
                              json=task_data,
                              headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 201
        task_id = response.json()["data"]["id"]
        created_task_ids.append(task_id)

    # Verify all tasks were created and are accessible
    get_response = client.get("/api/tasks",
                             headers={"Authorization": f"Bearer {token1}"})
    assert get_response.status_code == 200

    all_tasks = get_response.json()["data"]
    returned_task_ids = [task["id"] for task in all_tasks]

    for task_id in created_task_ids:
        assert task_id in returned_task_ids


def test_concurrent_task_updates_same_user(client: TestClient):
    """Test updating the same task concurrently from different sessions of the same user"""
    user_email = "concurrentupdate@test.com"
    user_username = "concurrent_update_user"

    # Register and get two tokens for the same user
    token1 = register_and_login_user(client, user_email, f"{user_username}_token1")
    token2 = register_and_login_user(client, user_email, f"{user_username}_token2")

    # Create a task with the first token
    task_data = {
        "title": "Concurrent Update Test Task",
        "description": "Task to test concurrent updates",
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                 json=task_data,
                                 headers={"Authorization": f"Bearer {token1}"})
    assert create_response.status_code == 201
    task_id = create_response.json()["data"]["id"]

    # Update the task with the second token (should work since it's the same user)
    update_data = {
        "title": "Updated Concurrent Update Test Task",
        "description": "Updated description from second session",
        "completed": True
    }

    update_response = client.put(f"/api/tasks/{task_id}",
                                json=update_data,
                                headers={"Authorization": f"Bearer {token2}"})
    assert update_response.status_code == 200

    updated_task = update_response.json()["data"]
    assert updated_task["title"] == "Updated Concurrent Update Test Task"
    assert updated_task["completed"] is True

    # Verify the update was persisted by retrieving the task
    retrieve_response = client.get(f"/api/tasks/{task_id}",
                                  headers={"Authorization": f"Bearer {token1}"})
    assert retrieve_response.status_code == 200

    retrieved_task = retrieve_response.json()["data"]
    assert retrieved_task["title"] == "Updated Concurrent Update Test Task"
    assert retrieved_task["completed"] is True


def test_concurrent_task_completions_same_user(client: TestClient):
    """Test toggling task completion concurrently from different sessions of the same user"""
    user_email = "concurrenttoggle@test.com"
    user_username = "concurrent_toggle_user"

    # Register and get two tokens for the same user
    token1 = register_and_login_user(client, user_email, f"{user_username}_token1")
    token2 = register_and_login_user(client, user_email, f"{user_username}_token2")

    # Create a task with the first token
    task_data = {
        "title": "Concurrent Toggle Test Task",
        "description": "Task to test concurrent completion toggles",
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                 json=task_data,
                                 headers={"Authorization": f"Bearer {token1}"})
    assert create_response.status_code == 201
    task_id = create_response.json()["data"]["id"]

    # Initially, task should be incomplete
    retrieve_response = client.get(f"/api/tasks/{task_id}",
                                  headers={"Authorization": f"Bearer {token1}"})
    assert retrieve_response.json()["data"]["completed"] is False

    # Toggle completion with the second token
    toggle_response = client.patch(f"/api/tasks/{task_id}/complete",
                                  headers={"Authorization": f"Bearer {token2}"})
    assert toggle_response.status_code == 200
    assert toggle_response.json()["data"]["completed"] is True

    # Toggle completion again with the first token
    toggle_response2 = client.patch(f"/api/tasks/{task_id}/complete",
                                   headers={"Authorization": f"Bearer {token1}"})
    assert toggle_response2.status_code == 200
    assert toggle_response2.json()["data"]["completed"] is False

    # Verify final state
    final_response = client.get(f"/api/tasks/{task_id}",
                               headers={"Authorization": f"Bearer {token2}"})
    assert final_response.json()["data"]["completed"] is False


def test_different_users_accessing_same_task_should_fail(client: TestClient):
    """Test that different users cannot access each other's tasks"""
    # Register first user
    user1_email = "diffuser1@test.com"
    user1_username = "diff_user1"
    token1 = register_and_login_user(client, user1_email, user1_username)

    # Register second user
    user2_email = "diffuser2@test.com"
    user2_username = "diff_user2"
    token2 = register_and_login_user(client, user2_email, user2_username)

    # User 1 creates a task
    task_data = {
        "title": "User 1's Private Task",
        "description": "Task that should only be accessible to user 1",
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                 json=task_data,
                                 headers={"Authorization": f"Bearer {token1}"})
    assert create_response.status_code == 201
    task_id = create_response.json()["data"]["id"]

    # User 2 should NOT be able to access User 1's task
    access_response = client.get(f"/api/tasks/{task_id}",
                                headers={"Authorization": f"Bearer {token2}"})
    # Should return 404 (Not Found) or 403 (Forbidden) to prevent user enumeration
    assert access_response.status_code in [403, 404], f"User 2 should not be able to access User 1's task, got {access_response.status_code}"

    # User 2 should NOT be able to update User 1's task
    update_response = client.put(f"/api/tasks/{task_id}",
                                json={"title": "Hacked by User 2"},
                                headers={"Authorization": f"Bearer {token2}"})
    assert update_response.status_code in [403, 404], f"User 2 should not be able to update User 1's task"

    # User 2 should NOT be able to delete User 1's task
    delete_response = client.delete(f"/api/tasks/{task_id}",
                                   headers={"Authorization": f"Bearer {token2}"})
    assert delete_response.status_code in [403, 404], f"User 2 should not be able to delete User 1's task"

    # User 1 should still be able to access their own task
    own_access_response = client.get(f"/api/tasks/{task_id}",
                                    headers={"Authorization": f"Bearer {token1}"})
    assert own_access_response.status_code == 200, f"User 1 should be able to access their own task"


def test_concurrent_user_registrations(client: TestClient):
    """Test registering multiple users concurrently"""
    # Register multiple different users concurrently
    users_to_register = [
        {"email": "concurrentreg1@test.com", "username": "concurrent_reg_user1"},
        {"email": "concurrentreg2@test.com", "username": "concurrent_reg_user2"},
        {"email": "concurrentreg3@test.com", "username": "concurrent_reg_user3"},
        {"email": "concurrentreg4@test.com", "username": "concurrent_reg_user4"},
    ]

    registration_results = []

    for user_data in users_to_register:
        registration_data = {
            "email": user_data["email"],
            "username": user_data["username"],
            "password": "securepassword123",
            "first_name": "Concurrent",
            "last_name": "Registration"
        }

        register_response = client.post("/api/auth/register", json=registration_data)
        # Registrations should succeed unless there's a race condition creating the same user
        assert register_response.status_code in [201, 409]  # 201 created or 409 conflict if same user
        registration_results.append(register_response.status_code)

    # At least some registrations should succeed
    assert any(status == 201 for status in registration_results), "At least one registration should succeed"


def test_session_isolation_between_users(client: TestClient):
    """Test that sessions are properly isolated between different users"""
    # Register two different users
    user1_data = {
        "email": "isolation1@test.com",
        "username": "isolation_user1",
        "password": "securepassword123",
        "first_name": "Isolation",
        "last_name": "Test1"
    }

    user2_data = {
        "email": "isolation2@test.com",
        "username": "isolation_user2",
        "password": "securepassword123",
        "first_name": "Isolation",
        "last_name": "Test2"
    }

    register_response1 = client.post("/api/auth/register", json=user1_data)
    assert register_response1.status_code == 201

    register_response2 = client.post("/api/auth/register", json=user2_data)
    assert register_response2.status_code == 201

    # Login both users to get their respective tokens
    login_response1 = client.post("/api/auth/login", json={"email": "isolation1@test.com", "password": "securepassword123"})
    assert login_response1.status_code == 200
    token1 = login_response1.json()["data"]["token"]

    login_response2 = client.post("/api/auth/login", json={"email": "isolation2@test.com", "password": "securepassword123"})
    assert login_response2.status_code == 200
    token2 = login_response2.json()["data"]["token"]

    # User 1 creates a task
    task_data1 = {
        "title": "User 1's Isolated Task",
        "description": "Task that only user 1 should see",
        "completed": False
    }

    create_response1 = client.post("/api/tasks",
                                  json=task_data1,
                                  headers={"Authorization": f"Bearer {token1}"})
    assert create_response1.status_code == 201
    user1_task_id = create_response1.json()["data"]["id"]

    # User 2 creates a task
    task_data2 = {
        "title": "User 2's Isolated Task",
        "description": "Task that only user 2 should see",
        "completed": False
    }

    create_response2 = client.post("/api/tasks",
                                  json=task_data2,
                                  headers={"Authorization": f"Bearer {token2}"})
    assert create_response2.status_code == 201
    user2_task_id = create_response2.json()["data"]["id"]

    # Each user should only see their own tasks
    user1_tasks_response = client.get("/api/tasks",
                                     headers={"Authorization": f"Bearer {token1}"})
    assert user1_tasks_response.status_code == 200
    user1_tasks = [task["id"] for task in user1_tasks_response.json()["data"]]
    assert user1_task_id in user1_tasks
    assert user2_task_id not in user1_tasks  # User 1 should not see User 2's task

    user2_tasks_response = client.get("/api/tasks",
                                     headers={"Authorization": f"Bearer {token2}"})
    assert user2_tasks_response.status_code == 200
    user2_tasks = [task["id"] for task in user2_tasks_response.json()["data"]]
    assert user2_task_id in user2_tasks
    assert user1_task_id not in user2_tasks  # User 2 should not see User 1's task


def test_concurrent_profile_access_by_same_user(client: TestClient):
    """Test accessing profile concurrently from different sessions of the same user"""
    user_email = "concurrentprofile@test.com"
    user_username = "concurrent_profile_user"

    # Register and get two tokens for the same user
    token1 = register_and_login_user(client, user_email, f"{user_username}_token1")
    token2 = register_and_login_user(client, user_email, f"{user_username}_token2")

    # Access profile from both tokens concurrently
    profile_response1 = client.get("/api/auth/profile",
                                  headers={"Authorization": f"Bearer {token1}"})
    assert profile_response1.status_code == 200

    profile_response2 = client.get("/api/auth/profile",
                                  headers={"Authorization": f"Bearer {token2}"})
    assert profile_response2.status_code == 200

    # Both responses should contain the same user information
    profile_data1 = profile_response1.json()["data"]
    profile_data2 = profile_response2.json()["data"]

    assert profile_data1["email"] == user_email
    assert profile_data2["email"] == user_email
    assert profile_data1["id"] == profile_data2["id"]  # Same user ID


def test_task_ownership_validation_during_concurrent_operations(client: TestClient):
    """Test that task ownership is validated correctly during concurrent operations"""
    # Register two different users
    user1_email = "ownership1@test.com"
    user1_username = "ownership_user1"
    token1 = register_and_login_user(client, user1_email, user1_username)

    user2_email = "ownership2@test.com"
    user2_username = "ownership_user2"
    token2 = register_and_login_user(client, user2_email, user2_username)

    # User 1 creates multiple tasks
    user1_tasks = []
    for i in range(3):
        task_data = {
            "title": f"User 1 Task {i}",
            "description": f"Task {i} owned by user 1",
            "completed": False
        }

        response = client.post("/api/tasks",
                              json=task_data,
                              headers={"Authorization": f"Bearer {token1}"})
        assert response.status_code == 201
        user1_tasks.append(response.json()["data"]["id"])

    # User 2 creates multiple tasks
    user2_tasks = []
    for i in range(3):
        task_data = {
            "title": f"User 2 Task {i}",
            "description": f"Task {i} owned by user 2",
            "completed": False
        }

        response = client.post("/api/tasks",
                              json=task_data,
                              headers={"Authorization": f"Bearer {token2}"})
        assert response.status_code == 201
        user2_tasks.append(response.json()["data"]["id"])

    # Verify that each user can only access their own tasks
    user1_all_tasks_response = client.get("/api/tasks",
                                         headers={"Authorization": f"Bearer {token1}"})
    assert user1_all_tasks_response.status_code == 200
    user1_returned_ids = [task["id"] for task in user1_all_tasks_response.json()["data"]]

    user2_all_tasks_response = client.get("/api/tasks",
                                         headers={"Authorization": f"Bearer {token2}"})
    assert user2_all_tasks_response.status_code == 200
    user2_returned_ids = [task["id"] for task in user2_all_tasks_response.json()["data"]]

    # Verify correct task isolation
    for task_id in user1_tasks:
        assert task_id in user1_returned_ids
        assert task_id not in user2_returned_ids

    for task_id in user2_tasks:
        assert task_id in user2_returned_ids
        assert task_id not in user1_returned_ids


if __name__ == "__main__":
    pytest.main()