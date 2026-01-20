import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.database.models.task import Task, TaskCreate


def test_task_creation():
    """Test basic task creation"""
    task_data = {
        "title": "Test task",
        "description": "Test description",
        "completed": False,
        "user_id": "user123"
    }

    task = Task(**task_data)

    assert task.title == "Test task"
    assert task.description == "Test description"
    assert task.completed is False
    assert task.user_id == "user123"


def test_task_create_schema():
    """Test TaskCreate schema validation"""
    task_create = TaskCreate(
        title="Test task",
        description="Test description",
        completed=False,
        due_date=None,
        user_id="user123"
    )

    assert task_create.title == "Test task"
    assert task_create.description == "Test description"
    assert task_create.completed is False
    assert task_create.user_id == "user123"