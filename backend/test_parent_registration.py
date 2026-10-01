from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

import server
from services import external_notifications as notifications


PASSWORD = "Guardian123"
SCHOOL_CODE = "SMH-AB12CD34EF"
ACCESS_CODE = "STU-ABCDEFGH"


class EmailEventCollection:
    def __init__(self):
        self.documents = []

    async def find_one(self, query):
        return next((event for event in self.documents if event["event_key"] == query["event_key"]), None)

    async def insert_one(self, document):
        self.documents.append(document)

    async def update_one(self, query, update):
        event = await self.find_one(query)
        if event:
            event.update(update["$set"])


class RecordingEmailProvider(notifications.EmailProvider):
    def __init__(self):
        self.messages = []

    async def send(self, *, to, subject, text):
        self.messages.append({"to": to, "subject": subject, "text": text})
        return "accepted-test-reference"


class FailingEmailProvider(notifications.EmailProvider):
    async def send(self, **_kwargs):
        raise notifications.NotificationProviderError("provider unavailable")


def configured_db(*, school=True, student=True, existing=None):
    database = MagicMock()
    school_doc = {
        "_id": "school-db-id", "id": "school-1", "name": "Test School", "school_code": SCHOOL_CODE,
        "is_active": True, "status": "active", "approval_status": "approved",
        "subscription_status": "active",
    } if school else None
    student_doc = {
        "id": "student-1", "school_id": "school-1", "student_access_code": ACCESS_CODE,
        "admission_number": "ADM-00001", "approval_status": "approved",
        "guardian_name": "Guardian One", "guardian_email": "guardian1@example.com",
        "secondary_guardian_name": "Guardian Two", "secondary_guardian_email": "Guardian2@Example.com",
    } if student else None
    database.schools.find_one = AsyncMock(return_value=school_doc)
    database.schools.update_one = AsyncMock()
    database.students.find_one = AsyncMock(return_value=student_doc)
    database.users.find_one = AsyncMock(return_value=existing)
    database.users.insert_one = AsyncMock()
    database.users.update_one = AsyncMock()
    database.auth_sessions.insert_one = AsyncMock()
    database.system_email_events = EmailEventCollection()
    return database


def client_for(monkeypatch, database):
    monkeypatch.setattr(server, "db", database)
    monkeypatch.setattr(server, "enforce_rate_limit", AsyncMock())
    monkeypatch.setattr(server, "log_security_event", AsyncMock())
    monkeypatch.setattr(server, "assert_login_not_locked", AsyncMock())
    monkeypatch.setattr(server, "clear_login_failures", AsyncMock())
    monkeypatch.setattr(server, "dispatch_notifications", AsyncMock(return_value={"succeeded": 0}))
    monkeypatch.setenv("SUPER_ADMIN_EMAIL", "owner@example.com")
    return TestClient(server.app)


@pytest.mark.parametrize("email", ["guardian1@example.com", "GUARDIAN2@example.COM"])
def test_either_recorded_guardian_can_register_and_sign_in(monkeypatch, email):
    database = configured_db()
    provider = RecordingEmailProvider()
    monkeypatch.setattr(notifications, "get_email_provider", lambda: provider)
    client = client_for(monkeypatch, database)
    registration = client.post("/api/auth/register-parent", json={
        "school_code": SCHOOL_CODE.lower(),
        "student_access_code": ACCESS_CODE.lower(),
        "email": email,
        "password": PASSWORD,
        "confirm_password": PASSWORD,
    })
    assert registration.status_code == 200, registration.text
    created = database.users.insert_one.await_args.args[0]
    assert created["email"] == email.lower()
    assert created["student_id"] == "student-1"
    assert created["student_ids"] == ["student-1"]
    assert created["role"] == "parent"
    assert server.verify_password(PASSWORD, created["password_hash"])
    assert len(provider.messages) == 1
    confirmation = provider.messages[0]
    assert confirmation["to"] == email.lower()
    assert created["full_name"] in confirmation["text"]
    assert "parent" in confirmation["text"]
    assert email.lower() in confirmation["text"]
    assert "Test School" in confirmation["text"]
    assert SCHOOL_CODE in confirmation["text"]
    assert database.system_email_events.documents[0]["status"] == "sent"

    database.users.find_one = AsyncMock(return_value=created)
    login = client.post("/api/auth/login", json={
        "school_code": SCHOOL_CODE,
        "email": email,
        "password": PASSWORD,
    })
    assert login.status_code == 200, login.text
    assert login.json()["user"]["role"] == "parent"


def test_unrelated_guardian_email_is_rejected(monkeypatch):
    database = configured_db()
    provider = RecordingEmailProvider()
    monkeypatch.setattr(notifications, "get_email_provider", lambda: provider)
    response = client_for(monkeypatch, database).post("/api/auth/register-parent", json={
        "school_code": SCHOOL_CODE,
        "student_access_code": ACCESS_CODE,
        "email": "stranger@example.com",
        "password": PASSWORD,
        "confirm_password": PASSWORD,
    })
    assert response.status_code == 403
    assert "does not match" in response.json()["detail"]
    database.users.insert_one.assert_not_awaited()
    assert provider.messages == []


def test_provider_failure_does_not_fail_successful_parent_registration(monkeypatch):
    database = configured_db()
    monkeypatch.setattr(notifications, "get_email_provider", lambda: FailingEmailProvider())

    response = client_for(monkeypatch, database).post("/api/auth/register-parent", json={
        "school_code": SCHOOL_CODE,
        "student_access_code": ACCESS_CODE,
        "email": "guardian1@example.com",
        "password": PASSWORD,
        "confirm_password": PASSWORD,
    })

    assert response.status_code == 200, response.text
    database.users.insert_one.assert_awaited_once()
    assert database.system_email_events.documents[0]["status"] == "failed"


def test_repeated_parent_registration_does_not_send_duplicate_confirmation(monkeypatch):
    database = configured_db()
    provider = RecordingEmailProvider()
    monkeypatch.setattr(notifications, "get_email_provider", lambda: provider)
    client = client_for(monkeypatch, database)
    payload = {
        "school_code": SCHOOL_CODE,
        "student_access_code": ACCESS_CODE,
        "email": "guardian1@example.com",
        "password": PASSWORD,
        "confirm_password": PASSWORD,
    }

    first = client.post("/api/auth/register-parent", json=payload)
    created = database.users.insert_one.await_args.args[0]
    database.users.find_one = AsyncMock(return_value=created)
    second = client.post("/api/auth/register-parent", json=payload)

    assert first.status_code == 200
    assert second.status_code == 409
    assert len(provider.messages) == 1


def test_legacy_join_endpoint_cannot_bypass_guardian_email_verification(monkeypatch):
    database = configured_db()
    response = client_for(monkeypatch, database).post("/api/auth/join-school", json={
        "school_code": SCHOOL_CODE,
        "email": "stranger@example.com",
        "password": PASSWORD,
        "full_name": "Unrelated Person",
        "role": "parent",
        "child_name": "Student One",
        "child_admission_number": ACCESS_CODE,
    })
    assert response.status_code == 400
    assert "Parent/Guardian Sign Up" in response.json()["detail"]
    database.users.insert_one.assert_not_awaited()


@pytest.mark.parametrize("school_exists,student_exists,expected", [
    (False, True, "Invalid school code"),
    (True, False, "Invalid student access code"),
])
def test_school_and_student_access_codes_are_validated(monkeypatch, school_exists, student_exists, expected):
    database = configured_db(school=school_exists, student=student_exists)
    response = client_for(monkeypatch, database).post("/api/auth/register-parent", json={
        "school_code": SCHOOL_CODE,
        "student_access_code": ACCESS_CODE,
        "email": "guardian1@example.com",
        "password": PASSWORD,
        "confirm_password": PASSWORD,
    })
    assert response.status_code == 404
    assert expected in response.json()["detail"]
    database.users.insert_one.assert_not_awaited()
