"""
Test script to validate the complete authentication flow with database integration
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from sqlmodel import create_engine, Session
from src.database.engine import engine
from src.services.user_service import UserService
from src.database.models.user import UserRegister, UserLogin
from src.auth.jwt_handler import verify_token


def test_full_auth_flow():
    """Test the complete authentication flow with database integration"""
    print("Testing full authentication flow with database integration...")

    # Create a database session
    with Session(engine) as session:
        # Test user registration
        print("\n1. Testing user registration...")
        user_data = UserRegister(
            email="test@example.com",
            username="testuser",
            password="pass123",  # Very short password to avoid bcrypt length limit
            first_name="Test",
            last_name="User"
        )

        try:
            created_user = UserService.create_user(session=session, user_create=user_data)
            print(f"+ User created successfully: {created_user.email}")
            print(f"  User ID: {created_user.id}")
        except Exception as e:
            print(f"- User creation failed: {e}")
            return False

        # Test user authentication/login
        print("\n2. Testing user authentication...")
        try:
            authenticated_user = UserService.authenticate_user(
                session=session,
                email="test@example.com",
                password="secure123"
            )

            if authenticated_user:
                print(f"+ User authenticated successfully: {authenticated_user.email}")

                # Create auth token
                auth_token = UserService.create_auth_token(authenticated_user)
                print(f"+ Authentication token created")

                # Verify the token
                token_payload = verify_token(auth_token)
                print(f"+ Token verified successfully for user: {token_payload.get('sub')}")
            else:
                print("- User authentication failed")
                return False
        except Exception as e:
            print(f"- User authentication failed: {e}")
            return False

        # Test getting user by ID
        print("\n3. Testing user retrieval by ID...")
        try:
            retrieved_user = UserService.get_user_by_id(session=session, user_id=created_user.id)
            if retrieved_user:
                print(f"+ User retrieved successfully: {retrieved_user.email}")
            else:
                print("- User retrieval failed")
                return False
        except Exception as e:
            print(f"- User retrieval failed: {e}")
            return False

    print("\n+ All authentication flow tests passed!")
    return True


if __name__ == "__main__":
    test_full_auth_flow()