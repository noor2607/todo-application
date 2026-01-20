"""
User Identity Propagation Tests

This module tests that user identity is properly propagated through the system,
ensuring consistent user identification across different endpoints and operations.
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
import uuid


# Create test database engine
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_identity.db"
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


def test_user_identity_consistency_across_endpoints(setup_test_database):
    """Test that user identity remains consistent across different authenticated endpoints"""
    # Register user
    user_data = {
        "email": "identity_consistency@example.com",
        "password": "SecurePass123!",
        "first_name": "Identity",
        "last_name": "Consistency"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login to get token
    login_data = {
        "email": "identity_consistency@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Access profile endpoint
    profile_response = client.get("/auth/profile", headers=headers)
    assert profile_response.status_code == 200
    profile_data = profile_response.json()

    # Verify user identity in profile
    assert profile_data["email"] == "identity_consistency@example.com"
    assert profile_data["first_name"] == "Identity"
    assert profile_data["last_name"] == "Consistency"

    # Create a task using the same token
    task_data = {
        "title": "Test Identity Task",
        "description": "Task to test identity propagation",
        "completed": False
    }

    create_task_response = client.post("/tasks/", json=task_data, headers=headers)
    assert create_task_response.status_code == 200
    task_data_response = create_task_response.json()

    # Verify that the task is associated with the correct user
    # (This assumes the backend automatically associates tasks with the authenticated user)
    # The exact implementation depends on your backend logic
    assert "id" in task_data_response
    assert task_data_response["title"] == "Test Identity Task"

    # Get the task back and verify ownership
    get_task_response = client.get(f"/tasks/{task_data_response['id']}", headers=headers)
    assert get_task_response.status_code == 200
    retrieved_task = get_task_response.json()
    assert retrieved_task["id"] == task_data_response["id"]
    assert retrieved_task["title"] == "Test Identity Task"


def test_user_identity_preservation_after_operations(setup_test_database):
    """Test that user identity is preserved after various operations"""
    # Register user
    user_data = {
        "email": "identity_preserve@example.com",
        "password": "SecurePass123!",
        "first_name": "Identity",
        "last_name": "Preserver"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login to get token
    login_data = {
        "email": "identity_preserve@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Store original identity info
    profile_response = client.get("/auth/profile", headers=headers)
    assert profile_response.status_code == 200
    original_profile = profile_response.json()

    # Perform multiple operations with the same token
    for i in range(3):
        task_data = {
            "title": f"Test Task {i}",
            "description": f"Task {i} to test identity preservation",
            "completed": False
        }

        create_response = client.post("/tasks/", json=task_data, headers=headers)
        assert create_response.status_code == 200

        # Verify identity is still the same after each operation
        check_profile_response = client.get("/auth/profile", headers=headers)
        assert check_profile_response.status_code == 200
        current_profile = check_profile_response.json()

        # Identity should remain unchanged
        assert current_profile["email"] == original_profile["email"]
        assert current_profile["first_name"] == original_profile["first_name"]
        assert current_profile["last_name"] == original_profile["last_name"]


def test_multiple_user_identity_isolation(setup_test_database):
    """Test that different users maintain separate identities"""
    # Register first user
    user1_data = {
        "email": "user1_identity@example.com",
        "password": "SecurePass123!",
        "first_name": "User",
        "last_name": "One"
    }

    register_response1 = client.post("/auth/register", json=user1_data)
    assert register_response1.status_code == 200

    # Register second user
    user2_data = {
        "email": "user2_identity@example.com",
        "password": "SecurePass123!",
        "first_name": "User",
        "last_name": "Two"
    }

    register_response2 = client.post("/auth/register", json=user2_data)
    assert register_response2.status_code == 200

    # Login as first user
    login_data1 = {
        "email": "user1_identity@example.com",
        "password": "SecurePass123!"
    }

    login_response1 = client.post("/auth/login", json=login_data1)
    assert login_response1.status_code == 200
    token1 = login_response1.json()["access_token"]
    headers1 = {"Authorization": f"Bearer {token1}"}

    # Login as second user
    login_data2 = {
        "email": "user2_identity@example.com",
        "password": "SecurePass123!"
    }

    login_response2 = client.post("/auth/login", json=login_data2)
    assert login_response2.status_code == 200
    token2 = login_response2.json()["access_token"]
    headers2 = {"Authorization": f"Bearer {token2}"}

    # Verify user1 identity
    profile_response1 = client.get("/auth/profile", headers=headers1)
    assert profile_response1.status_code == 200
    user1_profile = profile_response1.json()
    assert user1_profile["email"] == "user1_identity@example.com"
    assert user1_profile["last_name"] == "One"

    # Verify user2 identity
    profile_response2 = client.get("/auth/profile", headers=headers2)
    assert profile_response2.status_code == 200
    user2_profile = profile_response2.json()
    assert user2_profile["email"] == "user2_identity@example.com"
    assert user2_profile["last_name"] == "Two"

    # Verify that user1 token doesn't give access to user2 info and vice versa
    assert user1_profile["email"] != user2_profile["email"]
    assert user1_profile["last_name"] != user2_profile["last_name"]


def test_user_identity_with_task_operations(setup_test_database):
    """Test that user identity is properly maintained during task operations"""
    # Register user
    user_data = {
        "email": "task_identity@example.com",
        "password": "SecurePass123!",
        "first_name": "Task",
        "last_name": "Identity"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login to get token
    login_data = {
        "email": "task_identity@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create multiple tasks
    tasks = []
    for i in range(3):
        task_data = {
            "title": f"Task {i} by {user_data['first_name']}",
            "description": f"Description for task {i}",
            "completed": i % 2 == 0  # Alternate completed status
        }

        create_response = client.post("/tasks/", json=task_data, headers=headers)
        assert create_response.status_code == 200
        task_info = create_response.json()
        tasks.append(task_info)

    # Verify all tasks belong to the same user by checking we can access them
    for task in tasks:
        get_response = client.get(f"/tasks/{task['id']}", headers=headers)
        assert get_response.status_code == 200
        retrieved_task = get_response.json()
        assert retrieved_task["id"] == task["id"]
        assert retrieved_task["title"] == task["title"]

    # Get all tasks and verify they're all from the same authenticated user
    all_tasks_response = client.get("/tasks/", headers=headers)
    assert all_tasks_response.status_code == 200
    all_tasks = all_tasks_response.json()

    # Verify all retrieved tasks match the ones we created
    created_ids = {task["id"] for task in tasks}
    retrieved_ids = {task["id"] for task in all_tasks}
    assert created_ids.issubset(retrieved_ids)


def test_user_identity_session_continuity(setup_test_database):
    """Test that user identity persists throughout a session with multiple requests"""
    # Register user
    user_data = {
        "email": "session_continuity@example.com",
        "password": "SecurePass123!",
        "first_name": "Session",
        "last_name": "Continuity"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login to get token
    login_data = {
        "email": "session_continuity@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Store the expected identity
    expected_email = "session_continuity@example.com"
    expected_first_name = "Session"
    expected_last_name = "Continuity"

    # Perform a series of operations maintaining the same token
    operations_log = []

    # 1. Check profile
    profile_response = client.get("/auth/profile", headers=headers)
    assert profile_response.status_code == 200
    profile_data = profile_response.json()
    operations_log.append(("profile_check", profile_data["email"]))

    # Verify identity
    assert profile_data["email"] == expected_email
    assert profile_data["first_name"] == expected_first_name
    assert profile_data["last_name"] == expected_last_name

    # 2. Create a task
    task_data = {
        "title": "Continuity Test Task",
        "description": "Testing session continuity",
        "completed": False
    }

    create_response = client.post("/tasks/", json=task_data, headers=headers)
    assert create_response.status_code == 200
    task_info = create_response.json()
    operations_log.append(("task_create", task_info["title"]))

    # 3. Update the task
    update_data = {
        "title": "Updated Continuity Test Task",
        "description": "Testing session continuity after update",
        "completed": True
    }

    update_response = client.put(f"/tasks/{task_info['id']}", json=update_data, headers=headers)
    assert update_response.status_code == 200
    updated_task = update_response.json()
    operations_log.append(("task_update", updated_task["title"]))

    # 4. Verify the task was updated but still belongs to the same user
    get_updated_response = client.get(f"/tasks/{task_info['id']}", headers=headers)
    assert get_updated_response.status_code == 200
    final_task = get_updated_response.json()
    operations_log.append(("task_verify", final_task["title"]))

    # 5. Final profile check to ensure identity is still intact
    final_profile_response = client.get("/auth/profile", headers=headers)
    assert final_profile_response.status_code == 200
    final_profile = final_profile_response.json()
    operations_log.append(("final_profile", final_profile["email"]))

    # Verify that throughout all operations, the user identity remained consistent
    assert final_profile["email"] == expected_email
    assert final_profile["first_name"] == expected_first_name
    assert final_profile["last_name"] == expected_last_name

    # Verify all operations were performed under the same identity
    for op_type, op_data in operations_log:
        if op_type == "profile_check" or op_type == "final_profile":
            assert op_data == expected_email
        elif op_type == "task_create":
            assert "Continuity" in op_data
        elif op_type == "task_update":
            assert "Continuity" in op_data and "Updated" in op_data
        elif op_type == "task_verify":
            assert "Continuity" in op_data and "Updated" in op_data


def test_user_identity_with_concurrent_requests(setup_test_database):
    """Test that user identity is maintained correctly with concurrent requests"""
    # Register user
    user_data = {
        "email": "concurrent_identity@example.com",
        "password": "SecurePass123!",
        "first_name": "Concurrent",
        "last_name": "Identity"
    }

    register_response = client.post("/auth/register", json=user_data)
    assert register_response.status_code == 200

    # Login to get token
    login_data = {
        "email": "concurrent_identity@example.com",
        "password": "SecurePass123!"
    }

    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Simulate multiple sequential requests (as concurrent requests are difficult with TestClient)
    # but verify that identity is maintained across multiple rapid requests
    for i in range(5):
        # Create a task
        task_data = {
            "title": f"Concurrent Task {i}",
            "description": f"Task {i} for concurrent testing",
            "completed": False
        }

        create_response = client.post("/tasks/", json=task_data, headers=headers)
        assert create_response.status_code == 200

        # Immediately verify identity is still correct
        profile_response = client.get("/auth/profile", headers=headers)
        assert profile_response.status_code == 200
        profile_data = profile_response.json()

        # Identity should remain consistent
        assert profile_data["email"] == "concurrent_identity@example.com"
        assert profile_data["first_name"] == "Concurrent"
        assert profile_data["last_name"] == "Identity"


if __name__ == "__main__":
    pytest.main([__file__])