# Event Manager Company: Software QA Analyst/Developer Onboarding Assignment

Welcome to the Event Manager Company! As a newly hired Software QA Analyst/Developer and a student in software engineering, you are embarking on an exciting journey to contribute to our project aimed at developing a secure, robust REST API that supports JWT token-based OAuth2 authentication. This API serves as the backbone of our user management system and will eventually expand to include features for event management and registration.

# Setup and Preliminary Steps

1. **Fork the Project Repository**: Fork the [project repository](https://github.com/yourusername/event_manager) to your own GitHub account. This creates a copy of the repository under your account, allowing you to work on the project independently.

2. **Clone the Forked Repository**: Clone the forked repository to your local machine using the `git clone` command. This creates a local copy of the repository on your computer, enabling you to make changes and run the project locally.
```bash
git clone https://github.com/yourusername/event_manager.git 
```

3. **Verify the Project Setup**: Follow the steps in the instructor video to set up the project using [Docker](https://www.docker.com/). Docker allows you to package the application with all its dependencies into a standardized unit called a container. Verify that you can access the API documentation at `http://localhost/docs` and the database using [PGAdmin](https://www.pgadmin.org/) at `http://localhost:5050`.
```bash
docker-compose up
```
For running pytests:
```bash
docker compose exec fastapi pytest tests
```

# Issues

## Issue 1 : Analyze and fix pytest errors

1. **Description**: The project’s test suite is failing when run with pytest. This may be due to:
- Broken or outdated test fixtures.
- Incorrect or missing environment variables.
- Application bugs affecting test outcomes.

2. **Expected Outcome**:
- All pytests to pass successfully

3. **Resolution Steps**:
- Identified the failing tests by running the below
```bash
docker compose exec fastapi pytest tests
```
- Issue with test_users_api was mainly due to the missing fixtures in conftest.py
- Added the missing token fixtures to the conftest.py
- Identified issues with tests not matching the pydantic model specifications
- Modified conftest.py to match the pydantic model expectations
- Found issue with SMTP server not configured for email testing, Raised an Issue
- Fixed all the identified and reran tests

4. **Tests**:
Reran the tests using the below
```bash
docker compose exec fastapi pytest tests
```
![alt text](image.png)

## Issue 2 : Fix SMTP Server Configuration Issues

1. **Description**: The project uses an SMTP server for email functionality, and there are configuration issues preventing successful email testing. Tests are trying to connect to an SMTP server, but the server is either unavailable or not set up correctly for testing.

FAILED tests/test_email.py::test_send_markdown_email - smtplib.SMTPServerDisconnected: Connection unexpectedly closed
FAILED tests/test_services/test_user_service.py::test_create_user_with_valid_data - smtplib.SMTPServerDisconnected: Connection unexpectedly closed
FAILED tests/test_services/test_user_service.py::test_register_user_with_valid_data - smtplib.SMTPServerDisconnected: Connection unexpectedly closed

2. **Expected Outcome**:
The project is to be configured to send test emails using Mailtrap, enabling smoother development and debugging. run pytests that were failing due to SMTP issues and ensure successful run.

3. **Resolution Steps**: 
Setting up Mailtrap to enable local email testing will resolve the issue.

- Set Up a Mailtrap Account
Go to Mailtrap and create an account if you don’t have one.
After logging in: Create a new inbox or use the default one.
Copy the SMTP credentials (host, port, username, password)

- Configure the .env file for the below
smtp_server=
smtp_port=
smtp_username=
smtp_password=

- Rerun pytests to verify email functionality

- Check Mailtrap Inbox: Log in to Mailtrap and verify that emails appear in the specified inbox.

4. **Tests**:
- Test Email Service
![alt text](image-1.png)
- Test User Service
![alt text](image-2.png)

## Issue 3 : Fix SMTP Server Configuration Issues

1. **Description**: The current nickname validation allows underscores and hyphens. However, additional constraints are required:

- The nickname should not start with a number.
- Maximum length of 30 characters.
- Allow only alphanumeric characters, underscores (_), and hyphens (-).

2. **Expected Outcome**:

- Valid Nicknames: Nicknames such as john_doe, Test-User, and username123 should be accepted during user creation or update.
- Invalid Nicknames: Nicknames like 123username, invalid!, or toolong_nickname_that_exceeds_30_chars should be rejected.
- Validation Error Messages: Users attempting to create or update nicknames with invalid formats should get an error

3. **Resolution Steps**: 

- Added a helper function validate_nickname in user_schemas.py to encapsulate nickname validation logic
- Applied the validate_nickname function to relevant fields in UserBase, UserResponse and UserUpdate schemas using Pydantic validators. Added a @validator("nickname") decorator for runtime validation.
- Updated Tests - Extended test cases in tests/test_schemas/test_user_schemas.py to cover valid and invalid nickname scenarios

4. **Tests**:
Reran the tests using the below and the entire pytests, all ran successfully.
```bash
docker compose exec fastapi pytest tests/test_schemas/test_user_schemas.py
```
![alt text](image-3.png)