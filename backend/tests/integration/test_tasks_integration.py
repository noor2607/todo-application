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
        "email": "tasktest@test.com",
        "username": "task_test_user",
        "password": "securepassword123",
        "first_name": "Task",
        "last_name": "Test"
    }

    register_response = client.post("/api/auth/register", json=registration_data)
    assert register_response.status_code == 201

    # Login to get the token
    login_data = {
        "email": "tasktest@test.com",
        "password": "securepassword123"
    }

    login_response = client.post("/api/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["data"]["token"]
    return token


def test_task_crud_operations_flow(client: TestClient, valid_auth_token: str):
    """Test complete CRUD operations for tasks"""
    # Test creating a task
    task_data = {
        "title": "Integration Test Task",
        "description": "This is a test task for integration testing",
        "completed": False,
        "due_date": "2026-12-31T23:59:59"
    }

    create_response = client.post("/api/tasks",
                                  json=task_data,
                                  headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert create_response.status_code == 201

    created_data = create_response.json()
    assert created_data["success"] is True
    assert "data" in created_data
    assert created_data["data"]["title"] == "Integration Test Task"
    assert created_data["data"]["completed"] is False

    task_id = created_data["data"]["id"]
    assert isinstance(task_id, int)


def test_task_retrieve_single_task(client: TestClient, valid_auth_token: str):
    """Test retrieving a single task by ID"""
    # First create a task
    task_data = {
        "title": "Retrieve Test Task",
        "description": "Task to test retrieval",
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                  json=task_data,
                                  headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert create_response.status_code == 201

    task_id = create_response.json()["data"]["id"]

    # Retrieve the created task
    retrieve_response = client.get(f"/api/tasks/{task_id}",
                                   headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert retrieve_response.status_code == 200

    retrieved_data = retrieve_response.json()
    assert retrieved_data["success"] is True
    assert retrieved_data["data"]["id"] == task_id
    assert retrieved_data["data"]["title"] == "Retrieve Test Task"


def test_task_update_operation(client: TestClient, valid_auth_token: str):
    """Test updating a task"""
    # First create a task
    task_data = {
        "title": "Original Task Title",
        "description": "Original description",
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                  json=task_data,
                                  headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert create_response.status_code == 201

    task_id = create_response.json()["data"]["id"]

    # Update the task
    update_data = {
        "title": "Updated Task Title",
        "description": "Updated description",
        "completed": True
    }

    update_response = client.put(f"/api/tasks/{task_id}",
                                 json=update_data,
                                 headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert update_response.status_code == 200

    updated_data = update_response.json()
    assert updated_data["success"] is True
    assert updated_data["data"]["id"] == task_id
    assert updated_data["data"]["title"] == "Updated Task Title"
    assert updated_data["data"]["completed"] is True


def test_task_toggle_completion(client: TestClient, valid_auth_token: str):
    """Test toggling task completion status"""
    # First create a task
    task_data = {
        "title": "Toggle Completion Test",
        "description": "Task to test completion toggle",
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                  json=task_data,
                                  headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert create_response.status_code == 201

    task_id = create_response.json()["data"]["id"]

    # Verify initial state is not completed
    retrieve_response = client.get(f"/api/tasks/{task_id}",
                                   headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert retrieve_response.json()["data"]["completed"] is False

    # Toggle completion
    toggle_response = client.patch(f"/api/tasks/{task_id}/complete",
                                   headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert toggle_response.status_code == 200

    toggled_data = toggle_response.json()
    assert toggled_data["success"] is True
    assert toggled_data["data"]["id"] == task_id
    assert toggled_data["data"]["completed"] is True  # Should now be completed

    # Toggle again to set back to not completed
    toggle_response2 = client.patch(f"/api/tasks/{task_id}/complete",
                                    headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert toggle_response2.status_code == 200

    toggled_data2 = toggle_response2.json()
    assert toggled_data2["data"]["completed"] is False  # Should now be not completed


def test_task_delete_operation(client: TestClient, valid_auth_token: str):
    """Test deleting a task"""
    # First create a task
    task_data = {
        "title": "Delete Test Task",
        "description": "Task to test deletion",
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                  json=task_data,
                                  headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert create_response.status_code == 201

    task_id = create_response.json()["data"]["id"]

    # Verify task exists before deletion
    retrieve_response = client.get(f"/api/tasks/{task_id}",
                                   headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert retrieve_response.status_code == 200

    # Delete the task
    delete_response = client.delete(f"/api/tasks/{task_id}",
                                    headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert delete_response.status_code == 200

    deleted_data = delete_response.json()
    assert deleted_data["success"] is True

    # Verify task no longer exists
    retrieve_after_delete = client.get(f"/api/tasks/{task_id}",
                                       headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert retrieve_after_delete.status_code == 404


def test_task_list_retrieval(client: TestClient, valid_auth_token: str):
    """Test retrieving all tasks for a user"""
    # Create multiple tasks
    tasks_to_create = [
        {"title": "Task 1", "description": "First test task", "completed": False},
        {"title": "Task 2", "description": "Second test task", "completed": True},
        {"title": "Task 3", "description": "Third test task", "completed": False}
    ]

    task_ids = []
    for task_data in tasks_to_create:
        response = client.post("/api/tasks",
                               json=task_data,
                               headers={"Authorization": f"Bearer {valid_auth_token}"})
        assert response.status_code == 201
        task_ids.append(response.json()["data"]["id"])

    # Retrieve all tasks
    list_response = client.get("/api/tasks",
                               headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert list_response.status_code == 200

    list_data = list_response.json()
    assert list_data["success"] is True
    assert "data" in list_data
    assert isinstance(list_data["data"], list)

    # Check that all created tasks are in the response
    returned_task_ids = [task["id"] for task in list_data["data"]]
    for task_id in task_ids:
        assert task_id in returned_task_ids


def test_task_ownership_enforcement(client: TestClient):
    """Test that users can only access their own tasks"""
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
    # This should either return 404 (not found) or 403 (forbidden) depending on implementation
    # Both are acceptable for enforcing ownership
    assert access_response.status_code in [403, 404]


def test_task_filtering_and_sorting(client: TestClient, valid_auth_token: str):
    """Test task filtering and sorting functionality"""
    # Create tasks with different properties
    tasks_data = [
        {"title": "Completed Task", "description": "This task is completed", "completed": True, "due_date": "2025-12-31T23:59:59"},
        {"title": "Pending Task", "description": "This task is pending", "completed": False, "due_date": "2025-11-30T23:59:59"},
        {"title": "Another Pending Task", "description": "Another pending task", "completed": False, "due_date": "2025-10-31T23:59:59"}
    ]

    for task_data in tasks_data:
        response = client.post("/api/tasks",
                               json=task_data,
                               headers={"Authorization": f"Bearer {valid_auth_token}"})
        assert response.status_code == 201

    # Test filtering by status
    completed_filter_response = client.get("/api/tasks?status=completed",
                                           headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert completed_filter_response.status_code == 200
    completed_tasks = completed_filter_response.json()["data"]
    assert all(task["completed"] is True for task in completed_tasks)

    pending_filter_response = client.get("/api/tasks?status=pending",
                                         headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert pending_filter_response.status_code == 200
    pending_tasks = pending_filter_response.json()["data"]
    assert all(task["completed"] is False for task in pending_tasks)


if __name__ == "__main__":
    pytest.main()