from builtins import str
import pytest
from pydantic import ValidationError
from datetime import datetime
from app.schemas.user_schemas import UserBase, UserCreate, UserUpdate, UserResponse, UserListResponse, LoginRequest

# Tests for UserBase
def test_user_base_valid(user_base_data):
    user = UserBase(**user_base_data)
    assert user.nickname == user_base_data["nickname"]
    assert user.email == user_base_data["email"]

# Tests for UserCreate
def test_user_create_valid(user_create_data):
    user = UserCreate(**user_create_data)
    assert user.nickname == user_create_data["nickname"]
    assert user.password == user_create_data["password"]

# Tests for UserUpdate
def test_user_update_valid(user_update_data):
    user_update = UserUpdate(**user_update_data)
    assert user_update.email == user_update_data["email"]
    assert user_update.first_name == user_update_data["first_name"]

# Tests for UserResponse
def test_user_response_valid(user_response_data):
    user = UserResponse(**user_response_data)
    assert user.id == user_response_data["id"]
    # assert user.last_login_at == user_response_data["last_login_at"]

# Tests for LoginRequest
def test_login_request_valid(login_request_data):
    login = LoginRequest(**login_request_data)
    assert login.email == login_request_data["email"]
    assert login.password == login_request_data["password"]

# Parametrized tests for nickname and email validation
@pytest.mark.parametrize("nickname", ["test_user", "test-user", "testuser123", "123test"])
def test_user_base_nickname_valid(nickname, user_base_data):
    user_base_data["nickname"] = nickname
    user = UserBase(**user_base_data)
    assert user.nickname == nickname

@pytest.mark.parametrize("nickname", ["test user", "test?user", "", "us"])
def test_user_base_nickname_invalid(nickname):
    with pytest.raises(ValidationError) as exc_info:
        UserBase(email="test@example.com", nickname=nickname)
    error_message = str(exc_info.value)
    assert (
        "Nickname must start with a letter" in error_message
        or "String should have at least 3 characters" in error_message
    )

# Parametrized tests for URL validation
@pytest.mark.parametrize("url", ["http://valid.com/profile.jpg", "https://valid.com/profile.png", None])
def test_user_base_url_valid(url, user_base_data):
    user_base_data["profile_picture_url"] = url
    user = UserBase(**user_base_data)
    assert user.profile_picture_url == url

@pytest.mark.parametrize("url", ["ftp://invalid.com/profile.jpg", "http//invalid", "https//invalid"])
def test_user_base_url_invalid(url, user_base_data):
    user_base_data["profile_picture_url"] = url
    with pytest.raises(ValidationError):
        UserBase(**user_base_data)

# Tests for UserBase
def test_user_base_invalid_email(user_base_data_invalid):
    with pytest.raises(ValidationError) as exc_info:
        user = UserBase(**user_base_data_invalid)
    
    assert "value is not a valid email address" in str(exc_info.value)
    assert "john.doe.example.com" in str(exc_info.value)

# Tests for nickname

# Test valid nicknames for UserBase
@pytest.mark.parametrize("nickname", ["validName", "valid_name123", "valid-Name", "JohnDoe", "Alpha123"])
def test_user_base_nickname_valid(nickname):
    user = UserBase(email="test@example.com", nickname=nickname)
    assert user.nickname == nickname

# Test valid nicknames for UserCreate
@pytest.mark.parametrize("nickname", ["validName", "valid_name123", "valid-Name"])
def test_user_create_nickname_valid(nickname):
    user = UserCreate(email="validuser@example.com", password="Secure1234!", nickname=nickname)
    assert user.nickname == nickname

# Test invalid nicknames for UserCreate
@pytest.mark.parametrize("nickname", ["!invalidname", "invalid name", "ab", "toolongnickname12345678901234567890"])
def test_user_create_nickname_invalid(nickname):
    with pytest.raises(ValidationError) as exc_info:
        UserCreate(email="validuser@example.com", password="Secure1234!", nickname=nickname)
    assert "Nickname must start with a letter" in str(exc_info.value)

# Test valid nicknames for UserUpdate
@pytest.mark.parametrize("nickname", ["JohnDoe123", "nickname_1", "John-Doe", None])
def test_user_update_nickname_valid(nickname):
    if nickname is not None:
        user_update = UserUpdate(nickname=nickname)
        assert user_update.nickname == nickname
    else:
        # If None, we shouldn't trigger validation
        with pytest.raises(ValidationError):
            UserUpdate(nickname=nickname)

# Test invalid nicknames for UserUpdate
@pytest.mark.parametrize("nickname", ["", "12invalid", "@badname", "toolongnickname12345678901234567890"])
def test_user_update_nickname_invalid(nickname):
    with pytest.raises(ValidationError) as exc_info:
        UserUpdate(nickname=nickname)
    error_message = str(exc_info.value)
    assert (
        "Nickname must start with a letter" in error_message
        or "At least one field must be provided for update" in error_message
    )

# Test missing fields in UserUpdate (ensuring at least one field is provided)
def test_user_update_no_fields():
    with pytest.raises(ValidationError) as exc_info:
        UserUpdate()
    assert "At least one field must be provided for update" in str(exc_info.value)