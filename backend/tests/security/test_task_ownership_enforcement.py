"""
Task Ownership Enforcement Tests

This module tests that task ownership is properly enforced in the system,
ensuring users can only access, modify, and delete their own tasks.
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
from src.database.models.user import User
from src.database.models.task import Task


# Create test database engine
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_ownership.db"
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


def test_user_can_access_own_tasks(setup_test_database):
    """Test that users can access tasks they created"""
    # Register user
    user_data = {
        "email": "own_task_access@example.com",
        "password": "SecurePass123!",
        "first_name": "Own",
        "last_name": "Access"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login to get token
    login_data = {
        "email": "own_task_access@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create a task
    task_data = {
        "title": "My Own Task",
        "description": "This is my task that I should be able to access",
        "completed": False
    }

    create_response = client.post("/tasks/", json=task_data, headers=headers)
    assert create_response.status_code == 200
    task_id = create_response.json()["id"]

    # Verify user can access their own task
    get_response = client.get(f"/tasks/{task_id}", headers=headers)
    assert get_response.status_code == 200
    task = get_response.json()
    assert task["id"] == task_id
    assert task["title"] == "My Own Task"


def test_user_cannot_access_other_users_tasks(setup_test_database):
    """Test that users cannot access tasks created by other users"""
    # Register first user
    user1_data = {
        "email": "task_owner@example.com",
        "password": "SecurePass123!",
        "first_name": "Task",
        "last_name": "Owner"
    }

    register_response1 = client.post("/auth/register", json=user1_data)
    assert register_response1.status_code == 200

    # Register second user
    user2_data = {
        "email": "unauthorized_access@example.com",
        "password": "SecurePass123!",
        "first_name": "Unauthorized",
        "last_name": "Access"
    }

    register_response2 = client.post("/auth/register", json=user2_data)
    assert register_response2.status_code == 200

    # Login as first user and create a task
    login_data1 = {
        "email": "task_owner@example.com",
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
        "email": "unauthorized_access@example.com",
        "password": "SecurePass123!"
    }

    login_response2 = client.post("/auth/login", json=login_data2)
    assert login_response2.status_code == 200

    token2 = login_response2.json()["access_token"]
    headers2 = {"Authorization": f"Bearer {token2}"}

    # Verify second user cannot access first user's task
    get_response = client.get(f"/tasks/{task_id}", headers=headers2)
    assert get_response.status_code == 403  # Forbidden


def test_user_can_modify_own_tasks(setup_test_database):
    """Test that users can modify tasks they created"""
    # Register user
    user_data = {
        "email": "modify_own_task@example.com",
        "password": "SecurePass123!",
        "first_name": "Modify",
        "last_name": "Own"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login to get token
    login_data = {
        "email": "modify_own_task@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create a task
    task_data = {
        "title": "Original Task Title",
        "description": "Original description",
        "completed": False
    }

    create_response = client.post("/tasks/", json=task_data, headers=headers)
    assert create_response.status_code == 200
    task_id = create_response.json()["id"]

    # Modify the task
    update_data = {
        "title": "Updated Task Title",
        "description": "Updated description",
        "completed": True
    }

    update_response = client.put(f"/tasks/{task_id}", json=update_data, headers=headers)
    assert update_response.status_code == 200

    # Verify the task was updated
    get_response = client.get(f"/tasks/{task_id}", headers=headers)
    assert get_response.status_code == 200
    updated_task = get_response.json()
    assert updated_task["title"] == "Updated Task Title"
    assert updated_task["description"] == "Updated description"
    assert updated_task["completed"] is True


def test_user_cannot_modify_other_users_tasks(setup_test_database):
    """Test that users cannot modify tasks created by other users"""
    # Register first user
    user1_data = {
        "email": "task_creator@example.com",
        "password": "SecurePass123!",
        "first_name": "Task",
        "last_name": "Creator"
    }

    register_response1 = client.post("/auth/register", json=user1_data)
    assert register_response1.status_code == 200

    # Register second user
    user2_data = {
        "email": "unauthorized_modifier@example.com",
        "password": "SecurePass123!",
        "first_name": "Unauthorized",
        "last_name": "Modifier"
    }

    register_response2 = client.post("/auth/register", json=user2_data)
    assert register_response2.status_code == 200

    # Login as first user and create a task
    login_data1 = {
        "email": "task_creator@example.com",
        "password": "SecurePass123!"
    }

    login_response1 = client.post("/auth/login", json=login_data1)
    assert login_response1.status_code == 200

    token1 = login_response1.json()["access_token"]
    headers1 = {"Authorization": f"Bearer {token1}"}

    task_data = {
        "title": "Protected Task",
        "description": "This should only be modifiable by owner",
        "completed": False
    }

    create_response = client.post("/tasks/", json=task_data, headers=headers1)
    assert create_response.status_code == 200
    task_id = create_response.json()["id"]

    # Login as second user
    login_data2 = {
        "email": "unauthorized_modifier@example.com",
        "password": "SecurePass123!"
    }

    login_response2 = client.post("/auth/login", json=login_data2)
    assert login_response2.status_code == 200

    token2 = login_response2.json()["access_token"]
    headers2 = {"Authorization": f"Bearer {token2}"}

    # Try to modify the task - should fail
    update_data = {
        "title": "Hacked Task Title",
        "description": "Hacked description",
        "completed": True
    }

    update_response = client.put(f"/tasks/{task_id}", json=update_data, headers=headers2)
    assert update_response.status_code == 403  # Forbidden

    # Verify the original task is unchanged
    get_response = client.get(f"/tasks/{task_id}", headers=headers1)  # Use owner's token
    assert get_response.status_code == 200
    original_task = get_response.json()
    assert original_task["title"] == "Protected Task"  # Should still be original
    assert original_task["description"] == "This should only be modifiable by owner"
    assert original_task["completed"] is False


def test_user_can_delete_own_tasks(setup_test_database):
    """Test that users can delete tasks they created"""
    # Register user
    user_data = {
        "email": "delete_own_task@example.com",
        "password": "SecurePass123!",
        "first_name": "Delete",
        "last_name": "Own"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login to get token
    login_data = {
        "email": "delete_own_task@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create a task
    task_data = {
        "title": "Deletable Task",
        "description": "This task will be deleted",
        "completed": False
    }

    create_response = client.post("/tasks/", json=task_data, headers=headers)
    assert create_response.status_code == 200
    task_id = create_response.json()["id"]

    # Verify task exists
    get_response = client.get(f"/tasks/{task_id}", headers=headers)
    assert get_response.status_code == 200

    # Delete the task
    delete_response = client.delete(f"/tasks/{task_id}", headers=headers)
    assert delete_response.status_code == 200

    # Verify task no longer exists
    get_response_after_delete = client.get(f"/tasks/{task_id}", headers=headers)
    assert get_response_after_delete.status_code == 404


def test_user_cannot_delete_other_users_tasks(setup_test_database):
    """Test that users cannot delete tasks created by other users"""
    # Register first user
    user1_data = {
        "email": "task_preserver@example.com",
        "password": "SecurePass123!",
        "first_name": "Task",
        "last_name": "Preserver"
    }

    register_response1 = client.post("/auth/register", json=user1_data)
    assert register_response1.status_code == 200

    # Register second user
    user2_data = {
        "email": "unauthorized_deleter@example.com",
        "password": "SecurePass123!",
        "first_name": "Unauthorized",
        "last_name": "Deleter"
    }

    register_response2 = client.post("/auth/register", json=user2_data)
    assert register_response2.status_code == 200

    # Login as first user and create a task
    login_data1 = {
        "email": "task_preserver@example.com",
        "password": "SecurePass123!"
    }

    login_response1 = client.post("/auth/login", json=login_data1)
    assert login_response1.status_code == 200

    token1 = login_response1.json()["access_token"]
    headers1 = {"Authorization": f"Bearer {token1}"}

    task_data = {
        "title": "Protected Task",
        "description": "This should only be deletable by owner",
        "completed": False
    }

    create_response = client.post("/tasks/", json=task_data, headers=headers1)
    assert create_response.status_code == 200
    task_id = create_response.json()["id"]

    # Login as second user
    login_data2 = {
        "email": "unauthorized_deleter@example.com",
        "password": "SecurePass123!"
    }

    login_response2 = client.post("/auth/login", json=login_data2)
    assert login_response2.status_code == 200

    token2 = login_response2.json()["access_token"]
    headers2 = {"Authorization": f"Bearer {token2}"}

    # Try to delete the task - should fail
    delete_response = client.delete(f"/tasks/{task_id}", headers=headers2)
    assert delete_response.status_code == 403  # Forbidden

    # Verify the original task still exists and is unchanged
    get_response = client.get(f"/tasks/{task_id}", headers=headers1)  # Use owner's token
    assert get_response.status_code == 200
    preserved_task = get_response.json()
    assert preserved_task["title"] == "Protected Task"
    assert preserved_task["description"] == "This should only be deletable by owner"


def test_user_can_list_only_their_own_tasks(setup_test_database):
    """Test that users can only list tasks they created"""
    # Register first user
    user1_data = {
        "email": "list_owner1@example.com",
        "password": "SecurePass123!",
        "first_name": "List",
        "last_name": "Owner1"
    }

    register_response1 = client.post("/auth/register", json=user1_data)
    assert register_response1.status_code == 200

    # Register second user
    user2_data = {
        "email": "list_owner2@example.com",
        "password": "SecurePass123!",
        "first_name": "List",
        "last_name": "Owner2"
    }

    register_response2 = client.post("/auth/register", json=user2_data)
    assert register_response2.status_code == 200

    # Login as first user and create tasks
    login_data1 = {
        "email": "list_owner1@example.com",
        "password": "SecurePass123!"
    }

    login_response1 = client.post("/auth/login", json=login_data1)
    assert login_response1.status_code == 200

    token1 = login_response1.json()["access_token"]
    headers1 = {"Authorization": f"Bearer {token1}"}

    user1_tasks = []
    for i in range(3):
        task_data = {
            "title": f"User1 Task {i}",
            "description": f"Task {i} for user 1",
            "completed": i % 2 == 0
        }

        create_response = client.post("/tasks/", json=task_data, headers=headers1)
        assert create_response.status_code == 200
        user1_tasks.append(create_response.json())

    # Login as second user and create tasks
    login_data2 = {
        "email": "list_owner2@example.com",
        "password": "SecurePass123!"
    }

    login_response2 = client.post("/auth/login", json=login_data2)
    assert login_response2.status_code == 200

    token2 = login_response2.json()["access_token"]
    headers2 = {"Authorization": f"Bearer {token2}"}

    user2_tasks = []
    for i in range(2):
        task_data = {
            "title": f"User2 Task {i}",
            "description": f"Task {i} for user 2",
            "completed": i % 2 == 1
        }

        create_response = client.post("/tasks/", json=task_data, headers=headers2)
        assert create_response.status_code == 200
        user2_tasks.append(create_response.json())

    # Verify user1 only sees their own tasks
    user1_list_response = client.get("/tasks/", headers=headers1)
    assert user1_list_response.status_code == 200
    user1_tasks_list = user1_list_response.json()

    user1_created_ids = {task["id"] for task in user1_tasks}
    user1_retrieved_ids = {task["id"] for task in user1_tasks_list}
    assert user1_created_ids == user1_retrieved_ids  # User1 only sees their tasks

    # Verify user2 only sees their own tasks
    user2_list_response = client.get("/tasks/", headers=headers2)
    assert user2_list_response.status_code == 200
    user2_tasks_list = user2_list_response.json()

    user2_created_ids = {task["id"] for task in user2_tasks}
    user2_retrieved_ids = {task["id"] for task in user2_tasks_list}
    assert user2_created_ids == user2_retrieved_ids  # User2 only sees their tasks

    # Verify no overlap between the lists
    assert len(user1_retrieved_ids.intersection(user2_retrieved_ids)) == 0


def test_task_ownership_with_bulk_operations(setup_test_database):
    """Test task ownership enforcement with bulk operations"""
    # Register users
    users = []
    for i in range(3):
        user_data = {
            "email": f"bulk_user{i}@example.com",
            "password": "SecurePass123!",
            "first_name": f"BulkUser{i}",
            "last_name": f"Test"
        }

        register_response = client.post("/auth/register", json=user_data)
        assert register_response.status_code == 200
        users.append(user_data)

    tokens = []
    headers_list = []

    # Login all users and collect tokens
    for user in users:
        login_data = {
            "email": user["email"],
            "password": "SecurePass123!"
        }

        login_response = client.post("/auth/login", json=login_data)
        assert login_response.status_code == 200

        token = login_response.json()["access_token"]
        tokens.append(token)
        headers_list.append({"Authorization": f"Bearer {token}"})

    # Each user creates multiple tasks
    user_tasks = {}
    for i, (user, headers) in enumerate(zip(users, headers_list)):
        user_tasks[i] = []
        for j in range(2):
            task_data = {
                "title": f"User{i} Task {j}",
                "description": f"Task {j} for user {i}",
                "completed": False
            }

            create_response = client.post("/tasks/", json=task_data, headers=headers)
            assert create_response.status_code == 200
            user_tasks[i].append(create_response.json())

    # Verify each user can only access their own tasks
    for i, headers in enumerate(headers_list):
        # Get user's own tasks
        response = client.get("/tasks/", headers=headers)
        assert response.status_code == 200
        retrieved_tasks = response.json()

        # Verify the count is correct
        assert len(retrieved_tasks) == 2  # Each user created 2 tasks

        # Verify all retrieved tasks belong to the correct user
        retrieved_titles = {task["title"] for task in retrieved_tasks}
        expected_titles = {f"User{i} Task {j}" for j in range(2)}
        assert retrieved_titles == expected_titles


def test_task_ownership_enforcement_edge_cases(setup_test_database):
    """Test task ownership enforcement with edge cases"""
    # Register user
    user_data = {
        "email": "edge_case_test@example.com",
        "password": "SecurePass123!",
        "first_name": "Edge",
        "last_name": "Case"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login to get token
    login_data = {
        "email": "edge_case_test@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Test with non-existent task ID
    fake_task_id = 999999
    get_fake_response = client.get(f"/tasks/{fake_task_id}", headers=headers)
    # Should return 404 (Not Found) rather than 403 (Forbidden) for non-existent task
    # Actual status code depends on implementation - could be 404 or 403
    assert get_fake_response.status_code in [404, 403]

    # Test modifying non-existent task
    update_data = {
        "title": "Fake Update",
        "description": "Trying to update non-existent task",
        "completed": True
    }

    update_fake_response = client.put(f"/tasks/{fake_task_id}", json=update_data, headers=headers)
    assert update_fake_response.status_code in [404, 403]

    # Test deleting non-existent task
    delete_fake_response = client.delete(f"/tasks/{fake_task_id}", headers=headers)
    assert delete_fake_response.status_code in [404, 403]


if __name__ == "__main__":
    pytest.main([__file__])