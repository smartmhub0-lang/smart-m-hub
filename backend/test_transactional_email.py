import asyncio

from services import external_notifications as notifications


class EventCollection:
    def __init__(self):
        self.documents = []

    async def find_one(self, query):
        return next((item for item in self.documents if item["event_key"] == query["event_key"]), None)

    async def insert_one(self, document):
        self.documents.append(document)

    async def update_one(self, query, update):
        document = await self.find_one(query)
        if document:
            document.update(update["$set"])


class FakeDb:
    def __init__(self):
        self.system_email_events = EventCollection()


class RecordingEmailProvider(notifications.EmailProvider):
    def __init__(self):
        self.messages = []

    async def send(self, *, to, subject, text):
        self.messages.append({"to": to, "subject": subject, "text": text})
        return "provider-accepted"


class FailingEmailProvider(notifications.EmailProvider):
    async def send(self, **_kwargs):
        raise notifications.NotificationProviderError("unavailable")


def test_super_admin_welcome_email_is_disabled_by_default(monkeypatch):
    database = FakeDb()
    provider = RecordingEmailProvider()
    monkeypatch.delenv("SUPER_ADMIN_WELCOME_EMAIL_ENABLED", raising=False)
    monkeypatch.setattr(notifications, "get_email_provider", lambda: provider)

    result = asyncio.run(notifications.send_super_admin_welcome_email(database, email="owner@example.test"))

    assert result == {"status": "disabled"}
    assert provider.messages == []
    assert database.system_email_events.documents == []


def test_super_admin_welcome_email_sends_once_after_provider_acceptance(monkeypatch):
    database = FakeDb()
    provider = RecordingEmailProvider()
    monkeypatch.setenv("SUPER_ADMIN_WELCOME_EMAIL_ENABLED", "true")
    monkeypatch.setattr(notifications, "get_email_provider", lambda: provider)

    first = asyncio.run(notifications.send_super_admin_welcome_email(database, email=" Owner@Example.Test "))
    second = asyncio.run(notifications.send_super_admin_welcome_email(database, email="owner@example.test"))

    assert first == {"status": "sent", "provider_reference": "provider-accepted"}
    assert second == {"status": "already_sent"}
    assert len(provider.messages) == 1
    assert provider.messages[0]["to"] == "owner@example.test"
    assert provider.messages[0]["subject"] == "Welcome to Smart M Hub Super Admin"
    assert "owner and Super Admin" in provider.messages[0]["text"]
    assert "password" not in provider.messages[0]["text"].lower()
    assert database.system_email_events.documents[0]["status"] == "sent"


def test_super_admin_welcome_email_records_provider_failure_without_secret(monkeypatch):
    database = FakeDb()
    monkeypatch.setenv("SUPER_ADMIN_WELCOME_EMAIL_ENABLED", "true")
    monkeypatch.setattr(notifications, "get_email_provider", lambda: FailingEmailProvider())

    result = asyncio.run(notifications.send_super_admin_welcome_email(database, email="owner@example.test"))

    assert result == {"status": "failed"}
    event = database.system_email_events.documents[0]
    assert event["status"] == "failed"
    assert event["error_type"] == "NotificationProviderError"
