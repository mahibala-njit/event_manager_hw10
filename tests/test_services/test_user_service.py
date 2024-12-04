from builtins import range
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import AsyncMock
from app.dependencies import get_settings
from app.models.user_model import User
from app.services.user_service import UserService
from app.schemas.user_schemas import UserCreate, UserUpdate
from app.utils.security import validate_password
from app.utils.security import hash_password, verify_password
from app.dependencies import get_settings
    

pytestmark = pytest.mark.asyncio

# Test creating a user with valid data
async def test_create_user_with_valid_data(db_session, email_service):
    user_data = {
        "email": "valid_user@example.com",
        "password": "ValidPassword123!",
    }
    user = await UserService.create(db_session, user_data, email_service)
    assert user is not None
    assert user.email == user_data["email"]

# Test creating a user with invalid data
async def test_create_user_with_invalid_data(db_session, email_service):
    user_data = {
        "nickname": "",  # Invalid nickname
        "email": "invalidemail",  # Invalid email
        "password": "short",  # Invalid password
    }
    user = await UserService.create(db_session, user_data, email_service)
    assert user is None

# Test fetching a user by ID when the user exists
async def test_get_by_id_user_exists(db_session, user):
    retrieved_user = await UserService.get_by_id(db_session, user.id)
    assert retrieved_user.id == user.id

# Test fetching a user by ID when the user does not exist
async def test_get_by_id_user_does_not_exist(db_session):
    non_existent_user_id = "non-existent-id"
    retrieved_user = await UserService.get_by_id(db_session, non_existent_user_id)
    assert retrieved_user is None

# Test fetching a user by nickname when the user exists
async def test_get_by_nickname_user_exists(db_session, user):
    retrieved_user = await UserService.get_by_nickname(db_session, user.nickname)
    assert retrieved_user.nickname == user.nickname

# Test fetching a user by nickname when the user does not exist
async def test_get_by_nickname_user_does_not_exist(db_session):
    retrieved_user = await UserService.get_by_nickname(db_session, "non_existent_nickname")
    assert retrieved_user is None

# Test fetching a user by email when the user exists
async def test_get_by_email_user_exists(db_session, user):
    retrieved_user = await UserService.get_by_email(db_session, user.email)
    assert retrieved_user.email == user.email

# Test fetching a user by email when the user does not exist
async def test_get_by_email_user_does_not_exist(db_session):
    retrieved_user = await UserService.get_by_email(db_session, "non_existent_email@example.com")
    assert retrieved_user is None

# Test updating a user with valid data
async def test_update_user_valid_data(db_session, user):
    new_email = "updated_email@example.com"
    updated_user = await UserService.update(db_session, user.id, {"email": new_email})
    assert updated_user is not None
    assert updated_user.email == new_email

# Test updating a user with invalid data
async def test_update_user_invalid_data(db_session, user):
    updated_user = await UserService.update(db_session, user.id, {"email": "invalidemail"})
    assert updated_user is None

# Test deleting a user who exists
async def test_delete_user_exists(db_session, user):
    deletion_success = await UserService.delete(db_session, user.id)
    assert deletion_success is True

# Test attempting to delete a user who does not exist
async def test_delete_user_does_not_exist(db_session):
    non_existent_user_id = "non-existent-id"
    deletion_success = await UserService.delete(db_session, non_existent_user_id)
    assert deletion_success is False

# Test listing users with pagination
async def test_list_users_with_pagination(db_session, users_with_same_role_50_users):
    users_page_1 = await UserService.list_users(db_session, skip=0, limit=10)
    users_page_2 = await UserService.list_users(db_session, skip=10, limit=10)
    assert len(users_page_1) == 10
    assert len(users_page_2) == 10
    assert users_page_1[0].id != users_page_2[0].id

# Test registering a user with valid data
async def test_register_user_with_valid_data(db_session, email_service):
    user_data = {
        "email": "register_valid_user@example.com",
        "password": "RegisterValid123!",
    }
    user = await UserService.register_user(db_session, user_data, email_service)
    assert user is not None
    assert user.email == user_data["email"]

# Test attempting to register a user with invalid data
async def test_register_user_with_invalid_data(db_session, email_service):
    user_data = {
        "email": "registerinvalidemail",  # Invalid email
        "password": "short",  # Invalid password
    }
    user = await UserService.register_user(db_session, user_data, email_service)
    assert user is None

# Test successful user login
async def test_login_user_successful(db_session, verified_user):
    user_data = {
        "email": verified_user.nickname,
        "password": "MySuperPassword$1234",
    }
    logged_in_user = await UserService.login_user(db_session, user_data["email"], user_data["password"])
    assert logged_in_user is not None

# Test user login with incorrect email
async def test_login_user_incorrect_email(db_session):
    user = await UserService.login_user(db_session, "nonexistentuser@noway.com", "Password123!")
    assert user is None

# Test user login with incorrect password
async def test_login_user_incorrect_password(db_session, user):
    user = await UserService.login_user(db_session, user.email, "IncorrectPassword!")
    assert user is None

# Test account lock after maximum failed login attempts
async def test_account_lock_after_failed_logins(db_session, verified_user):
    max_login_attempts = get_settings().max_login_attempts
    for _ in range(max_login_attempts):
        await UserService.login_user(db_session, verified_user.nickname, "wrongpassword")
    
    is_locked = await UserService.is_account_locked(db_session, verified_user.email)
    assert is_locked, "The account should be locked after the maximum number of failed login attempts."

# Test resetting a user's password
async def test_reset_password(db_session, user):
    new_password = "NewPassword123!"
    reset_success = await UserService.reset_password(db_session, user.id, new_password)
    assert reset_success is True

# Test verifying a user's email
async def test_verify_email_with_token(db_session, user):
    token = "valid_token_example"  # This should be set in your user setup if it depends on a real token
    user.verification_token = token  # Simulating setting the token in the database
    await db_session.commit()
    result = await UserService.verify_email_with_token(db_session, user.id, token)
    assert result is True

# Test unlocking a user's account
async def test_unlock_user_account(db_session, locked_user):
    unlocked = await UserService.unlock_user_account(db_session, locked_user.id)
    assert unlocked, "The account should be unlocked"
    refreshed_user = await UserService.get_by_id(db_session, locked_user.id)
    assert not refreshed_user.is_locked, "The user should no longer be locked"

@pytest.mark.asyncio
async def test_create_user_with_unique_nickname(db_session: AsyncSession, email_service):
    """Test user creation with a unique nickname."""
    user_data = {
        "email": "unique@example.com",
        "password": "SecurePassword123!",
        "nickname": "unique_nickname"
    }

    new_user = await UserService.create(db_session, user_data, email_service)
    assert new_user is not None
    assert new_user.nickname == "unique_nickname"
    assert new_user.email == "unique@example.com"


@pytest.mark.asyncio
async def test_create_user_with_duplicate_nickname(db_session: AsyncSession, email_service, user):
    """Test user creation with a duplicate nickname fails."""
    user_data = {
        "email": "newuser@example.com",
        "password": "SecurePassword123!",
        "nickname": user.nickname  # Use an existing nickname
    }

    result = await UserService.create(db_session, user_data, email_service)
    assert result is None, "Creation should fail for duplicate nickname."


@pytest.mark.asyncio
async def test_create_user_with_auto_generated_unique_nickname(db_session: AsyncSession, email_service):
    """Test user creation with an auto-generated unique nickname."""
    user_data = {
        "email": "autogen@example.com",
        "password": "SecurePassword123!"
    }

    new_user = await UserService.create(db_session, user_data, email_service)
    assert new_user is not None
    assert new_user.nickname is not None
    assert new_user.email == "autogen@example.com"


@pytest.mark.asyncio
async def test_update_user_with_unique_nickname(db_session: AsyncSession, user):
    """Test updating user with a unique nickname."""
    updated_data = {
        "nickname": "new_unique_nickname"
    }

    updated_user = await UserService.update(db_session, user.id, updated_data)
    assert updated_user is not None
    assert updated_user.nickname == "new_unique_nickname"


@pytest.mark.asyncio
async def test_update_user_with_duplicate_nickname(db_session: AsyncSession, user, another_user):
    """Test updating user with a duplicate nickname fails."""
    updated_data = {
        "nickname": another_user.nickname  # Use an existing nickname
    }

    result = await UserService.update(db_session, user.id, updated_data)
    assert result is None, "Update should fail for duplicate nickname."


@pytest.mark.asyncio
async def test_create_user_fails_for_duplicate_email(db_session: AsyncSession, user, email_service):
    """Test user creation fails if the email already exists."""
    user_data = {
        "email": user.email,  # Use an existing email
        "password": "SecurePassword123!",
        "nickname": "unique_nickname"
    }

    result = await UserService.create(db_session, user_data, email_service)
    assert result is None, "Creation should fail for duplicate email."


@pytest.mark.asyncio
async def test_create_user_successful_with_no_nickname(db_session: AsyncSession, email_service):
    """Test user creation succeeds with no nickname provided."""
    user_data = {
        "email": "nonickname@example.com",
        "password": "SecurePassword123!"
    }

    new_user = await UserService.create(db_session, user_data, email_service)
    assert new_user is not None
    assert new_user.nickname is not None  # Nickname should be auto-generated

@pytest.mark.parametrize("password", [
    "Short1!",  # Too short
    "alllowercase1!",  # No uppercase
    "ALLUPPERCASE1!",  # No lowercase
    "NoNumbers!",  # No digits
    "NoSpecials1"  # No special characters
])
def test_invalid_passwords(password):
    with pytest.raises(ValueError):
        validate_password(password)


@pytest.mark.parametrize("password", [
    "ValidPass1!",  # Meets all criteria
    "Complex$123"  # Meets all criteria
])
def test_valid_passwords(password):
    assert validate_password(password) is True


@pytest.mark.asyncio
async def test_user_creation_with_valid_password(db_session: AsyncSession, email_service: AsyncMock):
    user_data = {
        "email": "testuser@example.com",
        "password": "ValidPass1!",
        "first_name": "Test",
        "last_name": "User",
    }
    created_user = await UserService.create(db_session, user_data, email_service)

    assert created_user is not None
    assert created_user.email == "testuser@example.com"
    assert created_user.first_name == "Test"
    assert created_user.last_name == "User"
    assert created_user.hashed_password is not None


@pytest.mark.asyncio
async def test_user_creation_with_invalid_password(db_session: AsyncSession, email_service: AsyncMock):
    user_data = {
        "email": "testuser@example.com",
        "password": "short1!",  # Invalid password
        "first_name": "Test",
        "last_name": "User",
    }
    created_user = await UserService.create(db_session, user_data, email_service)
    assert created_user is None


def test_password_hashing():
    plain_password = "SecurePass123!"
    hashed_password = hash_password(plain_password)

    # Ensure the hashed password is not the same as the plain password
    assert hashed_password != plain_password

    # Verify the hashed password matches the original password
    assert verify_password(plain_password, hashed_password)

def test_invalid_password_verification():
    plain_password = "SecurePass123!"
    wrong_password = "WrongPass123!"
    hashed_password = hash_password(plain_password)

    # Ensure wrong password does not match
    assert not verify_password(wrong_password, hashed_password)

@pytest.mark.asyncio
async def test_login_user_locked_account(db_session, locked_user):
    """Test login fails for locked accounts."""
    result = await UserService.login_user(db_session, locked_user.nickname, "correctpassword")
    assert result is None, "Login should fail for locked accounts"

@pytest.mark.asyncio
async def test_reset_password_for_nonexistent_user(db_session):
    """Test reset_password fails for non-existent users."""
    success = await UserService.reset_password(db_session, "non-existent-id", "NewPassword123!")
    assert success is False, "Reset should fail for non-existent users"
    