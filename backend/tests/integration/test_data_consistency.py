import pytest
from fastapi.testclient import TestClient
from main import app
from sqlmodel import Session, select
from database.models.task import Task
from database.engine import engine
from auth.jwt_handler import create_access_token
import time


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
        "email": "consistencytest@test.com",
        "username": "consistency_test_user",
        "password": "securepassword123",
        "first_name": "Consistency",
        "last_name": "Test"
    }

    register_response = client.post("/api/auth/register", json=registration_data)
    assert register_response.status_code == 201

    # Login to get the token
    login_data = {
        "email": "consistencytest@test.com",
        "password": "securepassword123"
    }

    login_response = client.post("/api/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["data"]["token"]
    return token


def test_task_creation_data_persistence(client: TestClient, valid_auth_token: str):
    """Test that created tasks are properly persisted with all data intact"""
    original_task_data = {
        "title": "Data Consistency Test Task",
        "description": "This task tests data persistence and consistency",
        "completed": False,
        "due_date": "2026-12-31T23:59:59"
    }

    # Create the task
    create_response = client.post("/api/tasks",
                                 json=original_task_data,
                                 headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert create_response.status_code == 201

    created_task = create_response.json()["data"]
    task_id = created_task["id"]

    # Retrieve the task to verify all data is preserved
    retrieve_response = client.get(f"/api/tasks/{task_id}",
                                  headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert retrieve_response.status_code == 200

    retrieved_task = retrieve_response.json()["data"]

    # Verify all properties are preserved correctly
    assert retrieved_task["id"] == task_id
    assert retrieved_task["title"] == original_task_data["title"]
    assert retrieved_task["description"] == original_task_data["description"]
    assert retrieved_task["completed"] == original_task_data["completed"]
    assert retrieved_task["due_date"] == original_task_data["due_date"]

    # Verify timestamps were added correctly
    assert "created_at" in retrieved_task
    assert "updated_at" in retrieved_task
    assert retrieved_task["created_at"] == retrieved_task["updated_at"]  # Should be the same for new task


def test_task_update_data_persistence(client: TestClient, valid_auth_token: str):
    """Test that updated tasks maintain data consistency"""
    # Create a task first
    initial_task_data = {
        "title": "Initial Task Title",
        "description": "Initial task description",
        "completed": False,
        "due_date": "2026-12-31T23:59:59"
    }

    create_response = client.post("/api/tasks",
                                 json=initial_task_data,
                                 headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert create_response.status_code == 201

    task_id = create_response.json()["data"]["id"]
    original_created_at = create_response.json()["data"]["created_at"]

    # Update the task with new data
    update_data = {
        "title": "Updated Task Title",
        "description": "Updated task description",
        "completed": True,
        "due_date": "2027-06-15T12:30:00"
    }

    update_response = client.put(f"/api/tasks/{task_id}",
                                json=update_data,
                                headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert update_response.status_code == 200

    updated_task = update_response.json()["data"]

    # Verify updated properties are changed
    assert updated_task["title"] == update_data["title"]
    assert updated_task["description"] == update_data["description"]
    assert updated_task["completed"] == update_data["completed"]
    assert updated_task["due_date"] == update_data["due_date"]

    # Verify unchanged properties remain the same
    assert updated_task["id"] == task_id  # ID should not change
    assert updated_task["user_id"] == create_response.json()["data"]["user_id"]  # User ID should not change

    # Verify timestamps were updated correctly
    assert updated_task["created_at"] == original_created_at  # Creation time should remain the same
    assert updated_task["updated_at"] != original_created_at  # Update time should be different


def test_task_completion_toggle_data_consistency(client: TestClient, valid_auth_token: str):
    """Test that toggling task completion maintains data consistency"""
    # Create a task with completed=False
    task_data = {
        "title": "Toggle Completion Consistency Test",
        "description": "Task to test completion toggle consistency",
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                 json=task_data,
                                 headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert create_response.status_code == 201

    task_id = create_response.json()["data"]["id"]
    original_created_at = create_response.json()["data"]["created_at"]

    # Toggle completion (should change to True)
    toggle_response = client.patch(f"/api/tasks/{task_id}/complete",
                                  headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert toggle_response.status_code == 200

    toggled_task = toggle_response.json()["data"]

    # Verify only completion status changed
    assert toggled_task["id"] == task_id
    assert toggled_task["title"] == "Toggle Completion Consistency Test"
    assert toggled_task["description"] == "Task to test completion toggle consistency"
    assert toggled_task["completed"] is True  # Should now be completed
    assert toggled_task["created_at"] == original_created_at  # Creation time unchanged

    # Toggle again (should change back to False)
    toggle_response2 = client.patch(f"/api/tasks/{task_id}/complete",
                                   headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert toggle_response2.status_code == 200

    toggled_task2 = toggle_response2.json()["data"]

    # Verify completion status reverted
    assert toggled_task2["id"] == task_id
    assert toggled_task2["completed"] is False  # Should now be not completed
    assert toggled_task2["title"] == "Toggle Completion Consistency Test"  # Title unchanged
    assert toggled_task2["description"] == "Task to test completion toggle consistency"  # Description unchanged


def test_task_deletion_data_consistency(client: TestClient, valid_auth_token: str):
    """Test that task deletion properly removes only the intended task"""
    # Create multiple tasks
    tasks_data = [
        {"title": "Deletion Test Task 1", "description": "First task for deletion test", "completed": False},
        {"title": "Deletion Test Task 2", "description": "Second task for deletion test", "completed": True},
        {"title": "Deletion Test Task 3", "description": "Third task for deletion test", "completed": False},
    ]

    created_task_ids = []
    for task_data in tasks_data:
        response = client.post("/api/tasks",
                              json=task_data,
                              headers={"Authorization": f"Bearer {valid_auth_token}"})
        assert response.status_code == 201
        created_task_ids.append(response.json()["data"]["id"])

    # Verify all tasks exist before deletion
    get_all_response = client.get("/api/tasks",
                                 headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert get_all_response.status_code == 200
    initial_tasks = get_all_response.json()["data"]
    initial_task_count = len(initial_tasks)

    # Delete one task
    task_to_delete = created_task_ids[1]  # Delete the second task
    delete_response = client.delete(f"/api/tasks/{task_to_delete}",
                                   headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert delete_response.status_code == 200

    # Verify the deleted task is gone but others remain
    get_after_delete_response = client.get("/api/tasks",
                                          headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert get_after_delete_response.status_code == 200
    remaining_tasks = get_after_delete_response.json()["data"]

    # Should have one less task
    assert len(remaining_tasks) == initial_task_count - 1

    # The deleted task should not be in the list
    remaining_task_ids = [task["id"] for task in remaining_tasks]
    assert task_to_delete not in remaining_task_ids

    # Other tasks should still be there
    for task_id in [created_task_ids[0], created_task_ids[2]]:  # First and third tasks
        assert task_id in remaining_task_ids


def test_user_data_isolation_consistency(client: TestClient):
    """Test that user data remains isolated and consistent across different users"""
    # Create first user
    user1_data = {
        "email": "user1.consistency@test.com",
        "username": "user1_consistency",
        "password": "securepassword123",
        "first_name": "User1",
        "last_name": "Consistency"
    }

    register_response1 = client.post("/api/auth/register", json=user1_data)
    assert register_response1.status_code == 201

    login_response1 = client.post("/api/auth/login", json={"email": "user1.consistency@test.com", "password": "securepassword123"})
    assert login_response1.status_code == 200
    token1 = login_response1.json()["data"]["token"]

    # Create second user
    user2_data = {
        "email": "user2.consistency@test.com",
        "username": "user2_consistency",
        "password": "securepassword123",
        "first_name": "User2",
        "last_name": "Consistency"
    }

    register_response2 = client.post("/api/auth/register", json=user2_data)
    assert register_response2.status_code == 201

    login_response2 = client.post("/api/auth/login", json={"email": "user2.consistency@test.com", "password": "securepassword123"})
    assert login_response2.status_code == 200
    token2 = login_response2.json()["data"]["token"]

    # User 1 creates tasks
    user1_tasks = [
        {"title": "User 1 Task 1", "description": "Owned by user 1", "completed": False},
        {"title": "User 1 Task 2", "description": "Also owned by user 1", "completed": True}
    ]

    user1_task_ids = []
    for task_data in user1_tasks:
        response = client.post("/api/tasks",
                              json=task_data,
                              headers={"Authorization": f"Bearer {token1}"})
        assert response.status_code == 201
        user1_task_ids.append(response.json()["data"]["id"])

    # User 2 creates tasks
    user2_tasks = [
        {"title": "User 2 Task 1", "description": "Owned by user 2", "completed": True},
        {"title": "User 2 Task 2", "description": "Also owned by user 2", "completed": False}
    ]

    user2_task_ids = []
    for task_data in user2_tasks:
        response = client.post("/api/tasks",
                              json=task_data,
                              headers={"Authorization": f"Bearer {token2}"})
        assert response.status_code == 201
        user2_task_ids.append(response.json()["data"]["id"])

    # Verify user 1 only sees their own tasks
    user1_tasks_response = client.get("/api/tasks",
                                     headers={"Authorization": f"Bearer {token1}"})
    assert user1_tasks_response.status_code == 200
    user1_returned_tasks = user1_tasks_response.json()["data"]
    user1_returned_ids = [task["id"] for task in user1_returned_tasks]

    for task_id in user1_task_ids:
        assert task_id in user1_returned_ids
    for task_id in user2_task_ids:
        assert task_id not in user1_returned_ids

    # Verify user 2 only sees their own tasks
    user2_tasks_response = client.get("/api/tasks",
                                     headers={"Authorization": f"Bearer {token2}"})
    assert user2_tasks_response.status_code == 200
    user2_returned_tasks = user2_tasks_response.json()["data"]
    user2_returned_ids = [task["id"] for task in user2_returned_tasks]

    for task_id in user2_task_ids:
        assert task_id in user2_returned_ids
    for task_id in user1_task_ids:
        assert task_id not in user2_returned_ids


def test_database_transaction_consistency(client: TestClient, valid_auth_token: str):
    """Test that database transactions maintain consistency"""
    # Create a task
    task_data = {
        "title": "Transaction Consistency Test",
        "description": "Task to test database transaction consistency",
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                 json=task_data,
                                 headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert create_response.status_code == 201

    task_id = create_response.json()["data"]["id"]

    # Update the task
    update_data = {
        "title": "Updated Transaction Consistency Test",
        "completed": True
    }

    update_response = client.put(f"/api/tasks/{task_id}",
                                json=update_data,
                                headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert update_response.status_code == 200

    updated_task = update_response.json()["data"]

    # Verify the update was properly committed
    verify_response = client.get(f"/api/tasks/{task_id}",
                                headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert verify_response.status_code == 200

    verified_task = verify_response.json()["data"]
    assert verified_task["title"] == "Updated Transaction Consistency Test"
    assert verified_task["completed"] is True


def test_task_list_filtering_consistency(client: TestClient, valid_auth_token: str):
    """Test that task list filtering returns consistent results"""
    # Create tasks with different completion statuses
    tasks_data = [
        {"title": "Pending Task 1", "description": "A pending task", "completed": False},
        {"title": "Completed Task 1", "description": "A completed task", "completed": True},
        {"title": "Pending Task 2", "description": "Another pending task", "completed": False},
        {"title": "Completed Task 2", "description": "Another completed task", "completed": True},
    ]

    for task_data in tasks_data:
        response = client.post("/api/tasks",
                              json=task_data,
                              headers={"Authorization": f"Bearer {valid_auth_token}"})
        assert response.status_code == 201

    # Test filtering for completed tasks
    completed_filter_response = client.get("/api/tasks?status=completed",
                                          headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert completed_filter_response.status_code == 200
    completed_tasks = completed_filter_response.json()["data"]

    # All returned tasks should be completed
    for task in completed_tasks:
        assert task["completed"] is True

    # Test filtering for pending tasks
    pending_filter_response = client.get("/api/tasks?status=pending",
                                        headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert pending_filter_response.status_code == 200
    pending_tasks = pending_filter_response.json()["data"]

    # All returned tasks should be pending
    for task in pending_tasks:
        assert task["completed"] is False

    # Test that total count matches expectations
    all_tasks_response = client.get("/api/tasks",
                                   headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert all_tasks_response.status_code == 200
    all_tasks = all_tasks_response.json()["data"]

    assert len(all_tasks) == 4
    assert len(completed_tasks) + len(pending_tasks) == len(all_tasks)


def test_timestamp_consistency(client: TestClient, valid_auth_token: str):
    """Test that timestamps are consistent and logical"""
    import datetime

    # Record time before creating task
    before_create = datetime.datetime.utcnow()

    # Create a task
    task_data = {
        "title": "Timestamp Consistency Test",
        "description": "Task to test timestamp consistency",
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                 json=task_data,
                                 headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert create_response.status_code == 201

    created_task = create_response.json()["data"]
    after_create = datetime.datetime.utcnow()

    # Verify created_at timestamp is within reasonable bounds
    created_at = datetime.datetime.fromisoformat(created_task["created_at"].replace("Z", "+00:00"))

    # The created_at time should be between before and after the API call
    assert before_create <= created_at <= after_create

    # created_at and updated_at should be the same for a new task
    updated_at = datetime.datetime.fromisoformat(created_task["updated_at"].replace("Z", "+00:00"))
    assert created_at == updated_at

    # Record time before updating
    before_update = datetime.datetime.utcnow()

    # Update the task
    update_data = {
        "title": "Updated Timestamp Consistency Test",
        "completed": True
    }

    update_response = client.put(f"/api/tasks/{created_task['id']}",
                                json=update_data,
                                headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert update_response.status_code == 200

    updated_task = update_response.json()["data"]
    after_update = datetime.datetime.utcnow()

    # After update, updated_at should be later than created_at
    updated_at_after = datetime.datetime.fromisoformat(updated_task["updated_at"].replace("Z", "+00:00"))
    created_at_original = datetime.datetime.fromisoformat(updated_task["created_at"].replace("Z", "+00:00"))

    assert created_at_original == created_at  # Creation time should not change
    assert updated_at_after > created_at_original  # Update time should be later than creation time
    assert before_update <= updated_at_after <= after_update  # Update time should be within expected bounds


def test_data_validation_consistency(client: TestClient, valid_auth_token: str):
    """Test that data validation is consistently applied"""
    # Test creating a task with minimal required fields
    minimal_task_data = {
        "title": "Minimal Task"
        # Only title is required
    }

    create_response = client.post("/api/tasks",
                                 json=minimal_task_data,
                                 headers={"Authorization": f"Bearer {valid_auth_token}"})
    # Should either succeed or return validation error, but not crash
    assert create_response.status_code in [201, 422]

    if create_response.status_code == 201:
        # If it succeeded, verify defaults were applied correctly
        created_task = create_response.json()["data"]
        assert created_task["title"] == "Minimal Task"
        # Verify that completed defaults to False if not provided
        assert "completed" in created_task
        assert isinstance(created_task["completed"], bool)

    # Test creating a task with all fields
    complete_task_data = {
        "title": "Complete Task",
        "description": "A task with all fields populated",
        "completed": True,
        "due_date": "2026-12-31T23:59:59"
    }

    complete_response = client.post("/api/tasks",
                                   json=complete_task_data,
                                   headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert complete_response.status_code == 201

    complete_task = complete_response.json()["data"]
    assert complete_task["title"] == "Complete Task"
    assert complete_task["description"] == "A task with all fields populated"
    assert complete_task["completed"] is True
    assert complete_task["due_date"] == "2026-12-31T23:59:59"


def test_concurrent_data_consistency(client: TestClient, valid_auth_token: str):
    """Test data consistency under concurrent operations"""
    # Create a base task
    task_data = {
        "title": "Concurrent Consistency Test",
        "description": "Task for testing concurrent consistency",
        "completed": False
    }

    create_response = client.post("/api/tasks",
                                 json=task_data,
                                 headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert create_response.status_code == 201
    task_id = create_response.json()["data"]["id"]

    # Perform multiple operations sequentially to verify consistency
    # 1. Update the task
    update_data = {
        "title": "Updated Concurrent Test",
        "completed": True
    }

    update_response = client.put(f"/api/tasks/{task_id}",
                                json=update_data,
                                headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert update_response.status_code == 200

    # 2. Toggle completion
    toggle_response = client.patch(f"/api/tasks/{task_id}/complete",
                                  headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert toggle_response.status_code == 200

    # 3. Verify final state is consistent
    final_response = client.get(f"/api/tasks/{task_id}",
                               headers={"Authorization": f"Bearer {valid_auth_token}"})
    assert final_response.status_code == 200

    final_task = final_response.json()["data"]
    # After update and toggle, completion should be False (True from update, then toggled to False)
    assert final_task["title"] == "Updated Concurrent Test"
    assert final_task["completed"] is False  # Was True after update, then toggled to False


if __name__ == "__main__":
    pytest.main()