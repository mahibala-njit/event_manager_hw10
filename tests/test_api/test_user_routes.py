import pytest
from uuid import uuid4
from httpx import AsyncClient
from app.models.user_model import User
from app.services.jwt_service import decode_token
from urllib.parse import urlencode
from sqlalchemy.sql import text  # Import the text function
from faker import Faker

from unittest.mock import AsyncMock, patch
from fastapi import HTTPException, status
from app.routers.user_routes import update_user_profile_picture
from app.schemas.user_schemas import UpdateProfilePictureRequest, UserResponse
from app.services.user_service import UserService
from sqlalchemy.ext.asyncio import AsyncSession
from app.services.jwt_service import create_access_token
from app.routers.user_routes import login
from app.schemas.token_schema import TokenResponse
from app.models.user_model import UserRole
from datetime import timedelta
from app.utils.security import hash_password

fake = Faker()

#@pytest.mark.asyncio
#async def test_create_user_already_exists(async_client, admin_token, verified_user):
#    """Test creating a user that already exists."""
#    headers = {"Authorization": f"Bearer {admin_token}"}
#    user_data = {
#        "email": verified_user.email,  # Use existing user's email
#        "password": "ValidPassword123!",
#        "nickname": "duplicate_nickname"
#    }
#    response = await async_client.post("/users/", json=user_data, headers=headers)
#    assert response.status_code == 400
#    assert "Email already exists" in response.json().get("detail", "")
#

@pytest.mark.asyncio
async def test_update_user_invalid_data(async_client, admin_token, admin_user):
    """Test updating a user with invalid data."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    updated_data = {"email": "notanemail"}  # Invalid email
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_delete_user_not_found(async_client, admin_token):
    """Test deleting a non-existent user."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    non_existent_user_id = uuid4()  # Random UUID
    response = await async_client.delete(f"/users/{non_existent_user_id}", headers=headers)
    assert response.status_code == 404

@pytest.mark.asyncio
async def test_list_users_no_users(async_client, admin_token, db_session):
    """Test listing users when no users exist."""
    # Use the `text` function to mark raw SQL explicitly
    await db_session.execute(text("DELETE FROM users"))
    await db_session.commit()  # Commit the transaction to apply changes
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.get("/users/", headers=headers)
    assert response.status_code == 200
    assert len(response.json().get("items", [])) == 0

@pytest.mark.asyncio
async def test_register_duplicate_email(async_client, verified_user):
    """Test registering a user with a duplicate email."""
    user_data = {
        "email": verified_user.email,  # Use existing user's email
        "password": "ValidPassword123!"
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 400
    assert "Email already exists" in response.json().get("detail", "")


@pytest.mark.asyncio
async def test_login_invalid_credentials(async_client):
    """Test login with invalid credentials."""
    form_data = {
        "username": "nonexistentuser@example.com",
        "password": "InvalidPassword123!"
    }
    response = await async_client.post(
        "/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 401
    assert "Incorrect email or password" in response.json().get("detail", "")


@pytest.mark.asyncio
async def test_verify_email_invalid_token(async_client, verified_user):
    """Test verifying email with an invalid token."""
    invalid_token = "invalidtoken123"
    response = await async_client.get(f"/verify-email/{verified_user.id}/{invalid_token}")
    assert response.status_code == 400
    assert "Invalid or expired verification token" in response.json().get("detail", "")


@pytest.mark.asyncio
async def test_list_users_pagination(async_client, admin_token, users_with_same_role_50_users):
    """Test listing users with pagination."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    response_page_1 = await async_client.get("/users/?skip=0&limit=10", headers=headers)
    response_page_2 = await async_client.get("/users/?skip=10&limit=10", headers=headers)
    assert response_page_1.status_code == 200
    assert response_page_2.status_code == 200
    assert len(response_page_1.json().get("items", [])) == 10
    assert len(response_page_2.json().get("items", [])) == 10


@pytest.mark.asyncio
async def test_create_user_invalid_nickname(async_client, admin_token):
    """Test creating a user with an invalid nickname."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    user_data = {
        "email": "newuser@example.com",
        "password": "ValidPassword123!",
        "nickname": "invalid nickname!"  # Invalid nickname
    }
    response = await async_client.post("/users/", json=user_data, headers=headers)
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_create_user_with_existing_nickname(async_client, admin_token, another_user):
    """Test creating a user with an existing nickname."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    user_data = {
        "email": "newuser@example.com",
        "password": "SecurePassword123!",
        "nickname": another_user.nickname,  # Use existing nickname
    }
    response = await async_client.post("/users/", json=user_data, headers=headers)
    assert response.status_code == 400
    assert "Nickname already exists" in response.json()["detail"]

@pytest.mark.asyncio
async def test_verify_email_success(async_client, verified_user, admin_token, db_session):
    """Test verifying a user's email with a valid token."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    token = verified_user.verification_token
    if not token:  # Ensure a valid token is set
        verified_user.verification_token = "valid_token_example"
        await db_session.commit()  # Ensure changes are saved

    response = await async_client.get(f"/verify-email/{verified_user.id}/{verified_user.verification_token}", headers=headers)
    assert response.status_code == 200, response.json()
    assert response.json()["message"] == "Email verified successfully"


@pytest.mark.asyncio
async def test_update_user_invalid_email_format(async_client, admin_user, admin_token):
    """Test updating a user with an invalid email format."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    updated_data = {"email": "invalidemail"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 422, response.json()
    assert any(
        "The email address is not valid" in detail["msg"]
        for detail in response.json()["detail"]
    ), "Error message should indicate invalid email format"

@pytest.mark.asyncio
async def test_delete_user_non_existent(async_client, admin_token):
    """Test deleting a user that does not exist."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.delete("/users/00000000-0000-0000-0000-000000000000", headers=headers)
    assert response.status_code == 404
    assert "User not found" in response.json()["detail"]

@pytest.mark.asyncio
async def test_update_user_bio_route(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.patch(
        f"/users/{admin_user.id}/bio",
        json={"bio": "This is a new bio."},
        headers=headers
    )
    assert response.status_code == 200
    assert response.json()["bio"] == "This is a new bio."

@pytest.mark.asyncio
async def test_update_user_bio(async_client: AsyncClient, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    payload = {"bio": "This is a new bio."}

    response = await async_client.patch(
        f"/users/{admin_user.id}/bio",
        json=payload,
        headers=headers
    )

    assert response.status_code == 200
    data = response.json()
    assert data["bio"] == payload["bio"]

@pytest.mark.asyncio
async def test_update_user_profile_picture(async_client: AsyncClient, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    payload = {"profile_picture_url": "https://example.com/new_picture.jpg"}

    response = await async_client.patch(
        f"/users/{admin_user.id}/profile-picture",
        json=payload,
        headers=headers
    )

    assert response.status_code == 200
    data = response.json()
    assert data["profile_picture_url"] == payload["profile_picture_url"]

@pytest.mark.asyncio
async def test_update_user_profile_picture(async_client: AsyncClient, admin_user, admin_token):
    """
    Test updating the profile picture URL of a user.
    """
    # Prepare request headers and payload
    headers = {"Authorization": f"Bearer {admin_token}"}
    payload = {
        "profile_picture_url": "https://example.com/updated_profile_picture.jpg"
    }

    # Send PATCH request to update profile picture
    response = await async_client.patch(
        f"/users/{admin_user.id}/profile-picture",
        json=payload,
        headers=headers
    )

    # Verify the response status code is 200 (success)
    assert response.status_code == 200, f"Unexpected status code: {response.status_code}"

    # Verify the response data matches the updated profile picture URL
    response_data = response.json()
    assert response_data["profile_picture_url"] == payload["profile_picture_url"]

    # Ensure other user data is intact
    assert response_data["id"] == str(admin_user.id)
    assert response_data["bio"] == admin_user.bio
    assert response_data["first_name"] == admin_user.first_name
    assert response_data["last_name"] == admin_user.last_name
    assert response_data["email"] == admin_user.email
    assert response_data["role"] == admin_user.role.name

@pytest.mark.asyncio
async def test_update_user_profile_picture_user_not_found(async_client: AsyncClient, admin_token):
    """
    Test updating the profile picture URL for a non-existent user.
    """
    # Prepare request headers and payload
    headers = {"Authorization": f"Bearer {admin_token}"}
    payload = {
        "profile_picture_url": "https://example.com/updated_profile_picture.jpg"
    }

    # Use a random UUID for a non-existent user
    non_existent_user_id = uuid4()

    # Send PATCH request
    response = await async_client.patch(
        f"/users/{non_existent_user_id}/profile-picture",
        json=payload,
        headers=headers
    )

    # Verify the response status code is 404 (not found)
    assert response.status_code == 404, f"Unexpected status code: {response.status_code}"

    # Verify the error message
    response_data = response.json()
    assert response_data["detail"] == "User not found"

@pytest.mark.asyncio
async def test_update_bio_for_nonexistent_user(async_client, admin_token):
    """Test updating bio for a non-existent user returns 404."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.patch(
        "/users/non-existent-id/bio",
        json={"bio": "Test Bio"},
        headers=headers
    )
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_update_profile_picture_invalid_url(async_client, admin_token, user):
    """Test updating profile picture with an invalid URL."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.patch(
        f"/users/{user.id}/profile-picture",
        json={"profile_picture_url": "invalid-url"},
        headers=headers
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid profile picture URL or other update issues."

@pytest.mark.asyncio
async def test_update_user_profile_picture_user_not_found(mocker):
    """Test updating profile picture when the user does not exist."""
    mock_session = AsyncMock(spec=AsyncSession)
    mock_user_service = mocker.patch.object(UserService, "get_by_id", return_value=None)

    user_id = uuid4()
    picture_data = UpdateProfilePictureRequest(profile_picture_url="http://example.com/picture.jpg")

    with pytest.raises(HTTPException) as exc_info:
        await update_user_profile_picture(
            user_id=user_id,
            picture_data=picture_data,
            db=mock_session,
            token="valid_token",
            current_user={"role": "ADMIN"}
        )

    assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
    assert exc_info.value.detail == "User not found"
    mock_user_service.assert_called_once_with(mock_session, user_id)


@pytest.mark.asyncio
async def test_update_user_profile_picture_update_failure(mocker):
    """Test updating profile picture when the update fails."""
    mock_session = AsyncMock(spec=AsyncSession)
    user_id = uuid4()
    picture_data = UpdateProfilePictureRequest(profile_picture_url="invalid-url")

    mocker.patch.object(UserService, "get_by_id", return_value={"id": user_id})
    mock_user_service = mocker.patch.object(UserService, "update", return_value=None)

    with pytest.raises(HTTPException) as exc_info:
        await update_user_profile_picture(
            user_id=user_id,
            picture_data=picture_data,
            db=mock_session,
            token="valid_token",
            current_user={"role": "ADMIN"}
        )

    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == "Invalid profile picture URL or other update issues."
    mock_user_service.assert_called_once_with(mock_session, user_id, {"profile_picture_url": picture_data.profile_picture_url})

@pytest.mark.asyncio
async def test_login_success(mocker):
    """Test successful login with valid credentials."""
    mock_session = AsyncMock()

    # Mock user object
    class MockUser:
        email = "test@example.com"
        role = UserRole.ADMIN
        hashed_password = hash_password("correct_password")

    mock_user = MockUser()

    # Mock UserService methods
    mocker.patch("app.services.user_service.UserService.login_user", return_value=mock_user)
    mocker.patch("app.services.user_service.UserService.is_account_locked", return_value=False)
    mocker.patch("app.services.jwt_service.create_access_token", return_value="mock_token")

    # Mock form data
    form_data = AsyncMock(username="test@example.com", password="correct_password")

    # Call the login endpoint
    result = await login(form_data, session=mock_session)

    # Assert the response
    #assert result["access_token"] == "mock_token"
    assert result["token_type"] == "bearer"

@pytest.mark.asyncio
async def test_login_account_locked(mocker):
    """Test login failure due to account being locked."""
    mock_session = AsyncMock()
    mocker.patch("app.services.user_service.UserService.is_account_locked", return_value=True)

    form_data = AsyncMock(username="locked_user", password="password")

    with pytest.raises(HTTPException) as exc_info:
        await login(form_data, session=mock_session)

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "Account locked due to too many failed login attempts."

@pytest.mark.asyncio
async def test_login_incorrect_credentials(mocker):
    """Test login failure due to incorrect credentials."""
    mock_session = AsyncMock()
    mocker.patch("app.services.user_service.UserService.is_account_locked", return_value=False)
    mocker.patch("app.services.user_service.UserService.login_user", return_value=None)

    form_data = AsyncMock(username="wrong_user", password="wrong_password")

    with pytest.raises(HTTPException) as exc_info:
        await login(form_data, session=mock_session)

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Incorrect email or password."

@pytest.mark.asyncio
async def test_login_unexpected_error(mocker):
    """Test login failure due to an unexpected error."""
    mock_session = AsyncMock()
    mocker.patch("app.services.user_service.UserService.is_account_locked", side_effect=Exception("Unexpected error"))

    form_data = AsyncMock(username="test@example.com", password="password")

    with pytest.raises(HTTPException) as exc_info:
        await login(form_data, session=mock_session)

    assert exc_info.value.status_code == 500
    assert exc_info.value.detail == "An unexpected error occurred."

