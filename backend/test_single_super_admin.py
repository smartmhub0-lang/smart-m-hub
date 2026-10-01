import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from passlib.context import CryptContext

from single_super_admin import (
    canonical_super_admin_email,
    is_canonical_super_admin,
    is_elevated_role,
    reconcile_single_super_admin,
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password):
    return pwd_context.hash(password)


def verify_password(password, password_hash):
    return pwd_context.verify(password, password_hash)


SUPER_ADMIN_EMAIL = "configured-admin@example.com"
DEPLOYED_SUPER_ADMIN_EMAIL = "chrisadundi1@gmail.com"
DEPLOYED_SUPER_ADMIN_PASSWORD = "C30758255c"


def test_only_configured_elevated_identity_is_canonical():
    with patch.dict(os.environ, {"SUPER_ADMIN_EMAIL": f"  {SUPER_ADMIN_EMAIL.upper()}  "}):
        assert canonical_super_admin_email() == SUPER_ADMIN_EMAIL
        assert is_canonical_super_admin({"email": SUPER_ADMIN_EMAIL, "role": "platform_admin"})
        assert not is_canonical_super_admin({"email": "other@example.com", "role": "super_admin"})
        assert not is_canonical_super_admin({"email": SUPER_ADMIN_EMAIL, "role": "school_admin"})


def test_super_admin_email_is_required():
    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(RuntimeError, match="SUPER_ADMIN_EMAIL is required"):
            canonical_super_admin_email()


def test_all_elevated_aliases_are_recognized_without_affecting_school_roles():
    for role in ["developer", "platform-admin", "platform_admin", "superadmin", "super_admin"]:
        assert is_elevated_role(role)
    for role in ["school_admin", "teacher", "finance", "secretary", "student", "parent"]:
        assert not is_elevated_role(role)


def test_reconcile_creates_one_hashed_active_super_admin():
    import asyncio

    users = MagicMock()
    users.update_many = AsyncMock()
    users.find.return_value.to_list = AsyncMock(return_value=[])
    users.find_one = AsyncMock(return_value=None)
    users.insert_one = AsyncMock()
    users.create_index = AsyncMock()
    database = MagicMock(users=users)
    hash_password = MagicMock(return_value="$2b$12$secure-hash")

    with patch.dict(os.environ, {"SUPER_ADMIN_EMAIL": SUPER_ADMIN_EMAIL, "SUPER_ADMIN_PASSWORD": "temporary-secret"}):
        result = asyncio.run(reconcile_single_super_admin(database, hash_password))

    assert result["email"] == SUPER_ADMIN_EMAIL
    hash_password.assert_called_once_with("temporary-secret")
    inserted = users.insert_one.await_args.args[0]
    assert inserted["password_hash"] == "$2b$12$secure-hash"
    assert inserted["is_active"] is True
    assert inserted["is_suspended"] is False
    assert inserted["approval_status"] == "approved"
    assert inserted["role"] == "super_admin"
    assert "temporary-secret" not in str(inserted)
    legacy_cleanup = users.update_many.await_args_list[0].args[1]
    assert legacy_cleanup["$unset"] == {"super_admin_guard": ""}
    users.create_index.assert_awaited_once()


def test_exact_deployed_super_admin_credentials_authenticate_after_reconciliation():
    import asyncio

    users = MagicMock()
    users.name = "users"
    users.update_many = AsyncMock()
    users.find.return_value.to_list = AsyncMock(return_value=[])
    users.find_one = AsyncMock(return_value=None)
    users.insert_one = AsyncMock()
    users.create_index = AsyncMock()
    database = MagicMock(users=users)
    database.name = "smart_m_hub_beta"

    with patch.dict(os.environ, {
        "SUPER_ADMIN_EMAIL": f"  {DEPLOYED_SUPER_ADMIN_EMAIL.upper()}  ",
        "SUPER_ADMIN_PASSWORD": DEPLOYED_SUPER_ADMIN_PASSWORD,
    }):
        result = asyncio.run(reconcile_single_super_admin(database, hash_password))

    inserted = users.insert_one.await_args.args[0]
    assert result["email"] == DEPLOYED_SUPER_ADMIN_EMAIL
    assert verify_password(DEPLOYED_SUPER_ADMIN_PASSWORD, inserted["password_hash"])
    assert inserted["role"] == "super_admin"
    assert inserted["status"] == "active"
    assert inserted["approval_status"] == "approved"
    assert inserted["is_active"] is True
    assert inserted["is_suspended"] is False
    assert inserted["is_blocked"] is False
    assert inserted["school_id"] is None
    assert DEPLOYED_SUPER_ADMIN_PASSWORD not in str(inserted)


def test_reconcile_updates_existing_singleton_when_configured_email_changes():
    import asyncio

    users = MagicMock()
    users.name = "users"
    users.update_many = AsyncMock()
    users.find.return_value.to_list = AsyncMock(return_value=[])
    users.find_one = AsyncMock(return_value={
        "_id": "existing-super-admin",
        "id": "existing-super-admin-id",
        "email": "previous-admin@example.test",
        "role": "super_admin",
        "super_admin_guard": "singleton",
        "password_hash": "$2b$12$previous-hash",
    })
    users.update_one = AsyncMock()
    users.insert_one = AsyncMock()
    users.create_index = AsyncMock()
    database = MagicMock(users=users)
    database.name = "smart_m_hub_beta"
    configured_password = "RotatedPassword123!"

    with patch.dict(os.environ, {
        "SUPER_ADMIN_EMAIL": "new-admin@example.test",
        "SUPER_ADMIN_PASSWORD": configured_password,
    }):
        result = asyncio.run(reconcile_single_super_admin(database, hash_password))

    assert result == {"id": "existing-super-admin-id", "email": "new-admin@example.test", "action": "updated"}
    users.insert_one.assert_not_awaited()
    users.update_one.assert_awaited_once()
    update = users.update_one.await_args.args[1]
    assert update["$set"]["email"] == "new-admin@example.test"
    assert update["$set"]["password_hash"] != configured_password
    assert verify_password(configured_password, update["$set"]["password_hash"])
    assert users.update_many.await_args.args[0]["$and"][1] == {"_id": {"$ne": "existing-super-admin"}}
