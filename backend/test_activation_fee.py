import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

from starlette.requests import Request

import server
from pricing import ACTIVATION_FEE_KES
from routes import platform


def test_new_school_registration_creates_kes_1000_activation_invoice(monkeypatch):
    database = SimpleNamespace(
        schools=SimpleNamespace(find_one=AsyncMock(return_value=None), create_index=AsyncMock(), insert_one=AsyncMock()),
        users=SimpleNamespace(find_one=AsyncMock(return_value=None), insert_one=AsyncMock()),
        platform_invoices=SimpleNamespace(insert_one=AsyncMock()),
    )
    monkeypatch.setattr(server, "db", database)
    monkeypatch.setattr(server, "enforce_rate_limit", AsyncMock())
    monkeypatch.setattr(server, "request_fingerprint", lambda *_args: "test")
    monkeypatch.setattr(server, "generate_school_code", AsyncMock(return_value="SMH-TESTCODE1"))
    monkeypatch.setattr(server, "generate_invite_code", lambda: "INVITE123")
    monkeypatch.setattr(server, "log_security_event", AsyncMock())
    monkeypatch.setattr(server, "send_registration_confirmation_email", AsyncMock())
    monkeypatch.setattr(server, "create_access_token", lambda _payload: "test-token")
    request = Request({
        "type": "http",
        "method": "POST",
        "path": "/api/auth/register-school",
        "headers": [(b"origin", b"https://school.example.test")],
        "client": ("127.0.0.1", 1234),
        "query_string": b"",
        "server": ("testserver", 443),
        "scheme": "https",
    })
    payload = server.RegisterSchoolRequest(
        name="Activation Test School",
        address="Test address",
        phone="+254700000000",
        email="school@example.com",
        school_type="primary",
        admin_name="Admin User",
        admin_email="admin@example.com",
        admin_password="StrongPassword123!",
    )

    result = asyncio.run(server.register_school(payload, request))

    school = database.schools.insert_one.await_args.args[0]
    invoice = database.platform_invoices.insert_one.await_args.args[0]
    assert ACTIVATION_FEE_KES == 1000
    assert school["activation_fee"] == 1000
    assert invoice["invoice_type"] == "activation"
    assert invoice["amount"] == 1000
    assert "activation fee" in invoice["description"].lower()
    assert result["activation_invoice"]["amount"] == 1000


def test_platform_pricing_reports_kes_1000_activation_fee(monkeypatch):
    database = SimpleNamespace(
        platform_settings=SimpleNamespace(find_one=AsyncMock(return_value={
            "subscription_plans": [{"name": "Standard", "monthly_amount": 2000, "installation_fee": 5000}],
        })),
        global_announcements=SimpleNamespace(find=lambda *_args: SimpleNamespace(
            sort=lambda *_sort: SimpleNamespace(to_list=AsyncMock(return_value=[])),
        )),
    )
    monkeypatch.setattr(platform, "db", database)

    result = asyncio.run(platform.platform_control({"role": "super_admin"}))

    assert result["pricing"]["activation_fee"] == 1000
    assert result["subscription_plans"][0]["activation_fee"] == 1000
    assert "installation_fee" not in result["subscription_plans"][0]
