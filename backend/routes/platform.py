import calendar
import asyncio
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict
from fastapi import APIRouter, Depends, HTTPException, status
from bson import ObjectId

from auth import get_current_user, db, hash_password, validate_password_strength
from services.external_notifications import (
    dispatch_notifications,
    normalize_email,
    normalize_kenyan_phone,
)


router = APIRouter(prefix="/api/platform", tags=["Platform Admin"])
APP_STARTED_AT = datetime.now(timezone.utc)
UPLOAD_ROOT = Path(__file__).resolve().parents[1] / "uploads"


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def notification_provider_status() -> dict:
    email_provider = os.getenv("EMAIL_PROVIDER", "disabled").strip().lower()
    sms_provider = os.getenv("SMS_PROVIDER", "disabled").strip().lower()
    email_ready = bool(os.getenv("EMAIL_FROM")) and (
        (email_provider == "smtp" and bool(os.getenv("SMTP_HOST")))
        or (email_provider in {"sendgrid", "resend"} and bool(os.getenv("EMAIL_API_KEY")))
    )
    sms_ready = (
        sms_provider in {"africastalking", "africas_talking"}
        and bool(os.getenv("SMS_API_KEY"))
        and bool(os.getenv("SMS_USERNAME"))
    ) or (
        sms_provider == "generic"
        and bool(os.getenv("SMS_API_KEY"))
        and bool(os.getenv("SMS_API_URL"))
    )
    return {
        "email": {"provider": email_provider, "configured": email_ready},
        "sms": {"provider": sms_provider, "configured": sms_ready},
    }


def school_lookup(school_id: str):
    conditions = [{"id": school_id}]
    if ObjectId.is_valid(school_id):
        conditions.append({"_id": ObjectId(school_id)})
    return {"$or": conditions}


def active_school_lookup(school_id: str):
    return {**school_lookup(school_id), "deleted_at": {"$exists": False}}


def serialize_doc(doc: dict):
    if not doc:
        return doc
    out = {}
    for key, value in doc.items():
        if key == "_id":
            continue
        out[key] = value.isoformat() if isinstance(value, datetime) else value
    return out


def money(value):
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0


def normalized_school_approval_status(school: dict) -> str:
    explicit = str(school.get("approval_status") or "").strip().lower()
    if explicit:
        return explicit

    status_value = str(school.get("status") or "").strip().lower()
    subscription_status = str(school.get("subscription_status") or "").strip().lower()
    if school.get("is_active") is True or status_value == "active" or subscription_status in {"active", "trial"}:
        return "approved"
    if status_value in {"rejected", "declined"}:
        return "rejected"
    return "pending"


def uptime_label():
    seconds = int((datetime.now(timezone.utc) - APP_STARTED_AT).total_seconds())
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _ = divmod(remainder, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def upload_storage_usage(school_id=None):
    total_bytes = 0
    total_files = 0
    root = UPLOAD_ROOT / str(school_id) if school_id else UPLOAD_ROOT
    if not root.exists():
        return {"used_mb": 0, "files": 0}
    for path in root.rglob("*"):
        if path.is_file():
            total_files += 1
            total_bytes += path.stat().st_size
    return {"used_mb": round(total_bytes / (1024 * 1024), 2), "files": total_files}


def is_today(value, today):
    if isinstance(value, datetime):
        return value.date().isoformat() == today
    return str(value or "").startswith(today)


def parse_date(value):
    if isinstance(value, datetime):
        return value.date()
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return datetime.strptime(str(value)[:10], "%Y-%m-%d").date()
        except ValueError:
            return None


def billing_due_date(today, billing_day):
    try:
        day = int(billing_day or today.day)
    except (TypeError, ValueError):
        day = today.day
    last_day = calendar.monthrange(today.year, today.month)[1]
    return today.replace(day=max(1, min(day, last_day)))


def invoice_number(school_code, billing_month):
    code = (school_code or "SCHOOL").upper().replace(" ", "")
    return f"SMH-SUB-{code}-{billing_month.replace('-', '')}"


async def ensure_subscription_invoice(school, due_date):
    school_id = str(school.get("id") or school.get("_id"))
    billing_month = due_date.strftime("%Y-%m")
    existing = await db.platform_invoices.find_one({
        "school_id": school_id,
        "invoice_type": "subscription",
        "billing_month": billing_month,
    })
    if existing:
        return existing, False

    now = now_iso()
    invoice = {
        "id": str(ObjectId()),
        "school_id": school_id,
        "school_name": school.get("name"),
        "school_code": school.get("school_code"),
        "invoice_type": "subscription",
        "invoice_number": invoice_number(school.get("school_code"), billing_month),
        "billing_month": billing_month,
        "amount": money(school.get("subscription_amount") or 2000),
        "currency": "KES",
        "status": "pending",
        "due_date": due_date.isoformat(),
        "description": "Monthly Smart M Hub subscription",
        "created_at": now,
        "updated_at": now,
    }
    await db.platform_invoices.insert_one(invoice)
    return invoice, True


async def create_subscription_reminder(school, invoice, reminder_type, days_until_due):
    school_id = str(school.get("id") or school.get("_id"))
    billing_month = invoice.get("billing_month")
    existing = await db.subscription_reminders.find_one({
        "school_id": school_id,
        "billing_month": billing_month,
        "reminder_type": reminder_type,
    })
    if existing:
        return False

    await db.subscription_reminders.insert_one({
        "id": str(ObjectId()),
        "school_id": school_id,
        "school_name": school.get("name"),
        "school_code": school.get("school_code"),
        "invoice_id": invoice.get("id"),
        "invoice_number": invoice.get("invoice_number"),
        "billing_month": billing_month,
        "reminder_type": reminder_type,
        "days_until_due": days_until_due,
        "status": "pending",
        "created_at": now_iso(),
    })
    await db.support_notices.insert_one({
        "id": str(ObjectId()),
        "school_id": school_id,
        "school_name": school.get("name"),
        "title": "Subscription payment reminder",
        "message": f"Your Smart M Hub subscription invoice {invoice.get('invoice_number')} is due in {days_until_due} day(s).",
        "notice_type": "payment_reminder",
        "severity": "warning" if days_until_due <= 5 else "info",
        "read_by": [],
        "created_by": "system",
        "created_at": now_iso(),
        "updated_at": now_iso(),
    })
    return True


async def require_super_admin(user=Depends(get_current_user)):
    if user.get("role") != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super admin access required"
        )
    return user


async def log_action(action, user, school_id=None, metadata=None):
    await db.audit_logs.insert_one({
        "action": action,
        "performed_by": user.get("email"),
        "user_id": user.get("user_id"),
        "school_id": school_id,
        "metadata": metadata or {},
        "timestamp": now_iso()
    })


def diagnostic_from_error(error: dict, note: dict = None):
    metadata = error.get("metadata") or {}
    message = metadata.get("message") or metadata.get("error") or error.get("action") or "System event"
    return {
        "id": str(error.get("id") or error.get("_id")),
        "source_id": str(error.get("id") or error.get("_id")),
        "message": message,
        "severity": metadata.get("severity") or ("high" if "failed" in str(error.get("action")) else "medium"),
        "status": (note or {}).get("status") or "new",
        "affected_file": metadata.get("affected_file") or metadata.get("file") or "Not captured",
        "route_or_component": metadata.get("route") or metadata.get("component") or metadata.get("endpoint") or "Not captured",
        "stack_trace": metadata.get("stack_trace") or metadata.get("traceback") or metadata.get("stack") or "",
        "suggested_fix": metadata.get("suggested_fix") or "Review the affected route/component, validate request data, and inspect recent audit logs.",
        "timestamp": error.get("timestamp") or error.get("created_at"),
        "action": error.get("action"),
        "school_id": error.get("school_id"),
        "performed_by": error.get("performed_by"),
        "fix_notes": (note or {}).get("fix_notes"),
        "reviewed_by": (note or {}).get("reviewed_by"),
        "reviewed_at": (note or {}).get("reviewed_at"),
    }


async def serialize_school(school: dict):
    school_id = str(school.get("id") or school.get("_id"))
    users = await db.users.find({"school_id": school_id}, {"_id": 0}).to_list(500)
    students_count = await db.students.count_documents({"school_id": school_id})
    payments = await db.payments.find({"school_id": school_id}, {"_id": 0}).to_list(500)
    invoices = await db.platform_invoices.find({"school_id": school_id}, {"_id": 0}).to_list(100)
    revenue = sum(money(p.get("amount")) for p in payments if p.get("status") in {"paid", "completed", "approved"})
    outstanding = sum(money(i.get("amount")) for i in invoices if i.get("status") in {"pending", "overdue"})
    admin = next((u for u in users if u.get("role") == "school_admin"), None)
    theme = school.get("theme") or {}

    return {
        "id": school_id,
        "mongo_id": str(school.get("_id")) if school.get("_id") else None,
        "name": school.get("name"),
        "logo_url": school.get("logo_url") or school.get("logo"),
        "school_code": school.get("school_code"),
        "school_type": school.get("school_type"),
        "administrator": admin.get("full_name") if admin else school.get("principal_name"),
        "administrator_email": admin.get("email") if admin else school.get("principal_email"),
        "administrator_phone": admin.get("phone") if admin else school.get("principal_phone"),
        "current_subscription": school.get("subscription_plan") or "standard",
        "subscription_status": school.get("subscription_status") or "inactive",
        "registration_date": school.get("created_at"),
        "last_login": max([u.get("last_login") for u in users if u.get("last_login")] or [None]),
        "payment_status": school.get("payment_status") or "pending",
        "payment_phone_number": school.get("payment_phone_number") or school.get("registration_payment_phone"),
        "payment_verification_status": school.get("payment_verification_status") or "awaiting_payment_phone",
        "school_status": school.get("status") or ("active" if school.get("is_active") else "inactive"),
        "approval_status": normalized_school_approval_status(school),
        "is_active": bool(school.get("is_active", False)),
        "email": school.get("email"),
        "phone": school.get("phone"),
        "address": school.get("address"),
        "login_link": school.get("login_link"),
        "theme": {
            "primary": theme.get("primary") or "#10B981",
            "secondary": theme.get("secondary") or "#0F172A",
        },
        "counts": {
            "users": len(users),
            "students": students_count,
            "payments": len(payments),
            "invoices": len(invoices),
        },
        "revenue": revenue,
        "outstanding": outstanding,
        "created_at": school.get("created_at"),
        "updated_at": school.get("updated_at"),
    }


def serialize_school_summary(school: dict, users: list, students_count: int, payments: list, invoices: list):
    school_id = str(school.get("id") or school.get("_id"))
    if isinstance(payments, dict):
        payments_count = int(payments.get("count") or 0)
        revenue = money(payments.get("revenue"))
    else:
        payments_count = len(payments)
        revenue = sum(money(p.get("amount")) for p in payments if p.get("status") in {"paid", "completed", "approved"})

    if isinstance(invoices, dict):
        invoices_count = int(invoices.get("count") or 0)
        outstanding = money(invoices.get("outstanding"))
    else:
        invoices_count = len(invoices)
        outstanding = sum(money(i.get("amount")) for i in invoices if i.get("status") in {"pending", "overdue"})

    admin = next((u for u in users if u.get("role") == "school_admin"), None)
    theme = school.get("theme") or {}

    return {
        "id": school_id,
        "mongo_id": str(school.get("_id")) if school.get("_id") else None,
        "name": school.get("name"),
        "logo_url": school.get("logo_url") or school.get("logo"),
        "school_code": school.get("school_code"),
        "school_type": school.get("school_type"),
        "administrator": admin.get("full_name") if admin else school.get("principal_name"),
        "administrator_email": admin.get("email") if admin else school.get("principal_email"),
        "administrator_phone": admin.get("phone") if admin else school.get("principal_phone"),
        "current_subscription": school.get("subscription_plan") or "standard",
        "subscription_status": school.get("subscription_status") or "inactive",
        "registration_date": school.get("created_at"),
        "last_login": max([u.get("last_login") for u in users if u.get("last_login")] or [None]),
        "payment_status": school.get("payment_status") or "pending",
        "payment_phone_number": school.get("payment_phone_number") or school.get("registration_payment_phone"),
        "payment_verification_status": school.get("payment_verification_status") or "awaiting_payment_phone",
        "school_status": school.get("status") or ("active" if school.get("is_active") else "inactive"),
        "approval_status": normalized_school_approval_status(school),
        "is_active": bool(school.get("is_active", False)),
        "email": school.get("email"),
        "phone": school.get("phone"),
        "address": school.get("address"),
        "login_link": school.get("login_link"),
        "theme": {
            "primary": theme.get("primary") or "#10B981",
            "secondary": theme.get("secondary") or "#0F172A",
        },
        "counts": {
            "users": len(users),
            "students": students_count,
            "payments": payments_count,
            "invoices": invoices_count,
        },
        "revenue": revenue,
        "outstanding": outstanding,
        "created_at": school.get("created_at"),
        "updated_at": school.get("updated_at"),
    }


@router.get("/metrics")
async def get_platform_metrics(user=Depends(require_super_admin)):
    today = datetime.now(timezone.utc).date().isoformat()
    schools = await db.schools.find(
        {},
        {"_id": 1, "id": 1, "is_active": 1, "status": 1, "subscription_status": 1, "created_at": 1, "approval_status": 1}
    ).to_list(5000)
    payments = await db.payments.find(
        {"status": {"$in": ["paid", "completed", "approved"]}},
        {"_id": 0, "amount": 1}
    ).to_list(10000)
    invoices = await db.platform_invoices.find(
        {"status": {"$in": ["paid", "pending", "overdue"]}},
        {"_id": 0, "amount": 1, "status": 1}
    ).to_list(10000)

    paid_revenue = sum(money(p.get("amount")) for p in payments)
    invoice_revenue = sum(money(i.get("amount")) for i in invoices if i.get("status") == "paid")
    outstanding = sum(money(i.get("amount")) for i in invoices if i.get("status") in {"pending", "overdue"})

    return {
        "total_registered_schools": len(schools),
        "total_schools": len(schools),
        "active_schools": sum(1 for s in schools if s.get("is_active") is True or normalized_school_approval_status(s) == "approved"),
        "suspended_schools": sum(1 for s in schools if str(s.get("status")).lower() == "suspended"),
        "trial_schools": sum(1 for s in schools if s.get("subscription_status") == "trial"),
        "monthly_revenue": paid_revenue + invoice_revenue,
        "outstanding_revenue": outstanding,
        "new_registrations": sum(1 for s in schools if str(s.get("created_at", "")).startswith(today)),
        "pending_approvals": sum(1 for s in schools if normalized_school_approval_status(s) == "pending"),
        "open_support_tickets": await db.support_tickets.count_documents({"status": {"$in": ["open", None]}}),
        "system_health": "operational",
        "active_users": await db.users.count_documents({"is_active": {"$ne": False}}),
        "daily_login_statistics": await db.users.count_documents({"last_login": {"$regex": f"^{today}"}}),
        "total_users": await db.users.count_documents({}),
        "total_revenue": paid_revenue + invoice_revenue,
        "storage_usage": {"used_mb": 0, "files": 0, "deferred": True},
        "api_activity_today": await db.audit_logs.count_documents({"timestamp": {"$regex": f"^{today}"}}),
        "failed_logins_today": await db.audit_logs.count_documents({"action": "login_failed", "timestamp": {"$regex": f"^{today}"}}),
        "overdue_invoices": sum(1 for i in invoices if i.get("status") == "overdue"),
    }


@router.get("/system-health")
async def system_health(user=Depends(require_super_admin)):
    database_status = "connected"
    try:
        await db.command("ping")
    except Exception as exc:
        database_status = f"error: {str(exc)}"

    collections = {}
    for name in ["schools", "users", "students", "payments", "platform_invoices", "support_tickets", "audit_logs"]:
        try:
            collections[name] = await db[name].count_documents({})
        except Exception:
            collections[name] = None

    errors = await db.audit_logs.find({"action": {"$regex": "error|failed|blocked", "$options": "i"}}, {"_id": 0}).sort("timestamp", -1).limit(20).to_list(20)
    alerts = await system_alerts(user)
    pending_jobs = await db.subscription_reminders.count_documents({"status": "pending"})
    maintenance = await db.platform_settings.find_one({}, {"_id": 0}) or {}
    return {
        "database_status": database_status,
        "api_status": "ok",
        "authentication_status": "ok",
        "server_status": "running",
        "platform_status": "maintenance" if maintenance.get("maintenance_mode") else "operational",
        "background_jobs": {"pending_subscription_reminders": pending_jobs},
        "latest_errors": errors,
        "alerts": alerts,
        "system_version": "1.0.0",
        "uptime": uptime_label(),
        "started_at": APP_STARTED_AT.isoformat(),
        "collections": collections,
        "storage_usage": upload_storage_usage(),
        "audit_events": await db.audit_logs.count_documents({}),
        "open_support_tickets": await db.support_tickets.count_documents({"status": {"$in": ["open", None]}}),
        "timestamp": now_iso(),
    }


@router.get("/notifications/status")
async def notification_status(user=Depends(require_super_admin)):
    return notification_provider_status()


@router.post("/notifications/test")
async def send_test_notification(data: dict, user=Depends(require_super_admin)):
    email = normalize_email(data.get("email"))
    phone = normalize_kenyan_phone(data.get("phone"))
    if not email and not phone:
        raise HTTPException(status_code=400, detail="A valid email address or Kenyan phone number is required")
    channels = []
    if email:
        channels.append("email")
    if phone:
        channels.append("sms")
    delivery = await dispatch_notifications(
        db,
        school_id="platform",
        title="Smart M Hub notification test",
        message="This is a delivery test from Smart M Hub. Email and SMS notifications are working when this message is received.",
        recipients=[{
            "id": user.get("user_id"),
            "school_id": "platform",
            "email": email,
            "phone": phone,
        }],
        channels=channels,
        event_type="platform_notification_test",
        requested_by=user.get("user_id"),
    )
    return {"delivery": delivery, "providers": notification_provider_status()}


@router.get("/schools")
async def get_all_schools(
    page: int = 1,
    limit: int = 100,
    search: str = "",
    user=Depends(require_super_admin),
):
    page = max(1, int(page or 1))
    limit = max(1, min(int(limit or 100), 200))
    query = {"deleted_at": {"$exists": False}}
    normalized_search = str(search or "").strip()
    if normalized_search:
        pattern = {"$regex": re.escape(normalized_search), "$options": "i"}
        query["$or"] = [{"name": pattern}, {"school_code": pattern}, {"email": pattern}]
    total = await db.schools.count_documents(query)
    school_docs = await db.schools.find(query).sort("created_at", -1).skip((page - 1) * limit).limit(limit).to_list(limit)
    school_ids = [str(school.get("id") or school.get("_id")) for school in school_docs]

    users_by_school = defaultdict(list)
    async for user_doc in db.users.find(
        {"school_id": {"$in": school_ids}},
        {"_id": 0, "school_id": 1, "role": 1, "full_name": 1, "email": 1, "phone": 1, "last_login": 1}
    ):
        users_by_school[str(user_doc.get("school_id"))].append(user_doc)

    students_by_school = defaultdict(int)
    async for row in db.students.aggregate([
        {"$match": {"school_id": {"$in": school_ids}}},
        {"$group": {"_id": "$school_id", "count": {"$sum": 1}}},
    ]):
        students_by_school[str(row.get("_id"))] = int(row.get("count") or 0)

    payments_by_school = defaultdict(lambda: {"count": 0, "revenue": 0})
    async for row in db.payments.aggregate([
        {"$match": {"school_id": {"$in": school_ids}}},
        {"$group": {
            "_id": "$school_id",
            "count": {"$sum": 1},
            "revenue": {
                "$sum": {
                    "$cond": [
                        {"$in": ["$status", ["paid", "completed", "approved"]]},
                        {"$ifNull": ["$amount", 0]},
                        0,
                    ]
                }
            },
        }},
    ]):
        payments_by_school[str(row.get("_id"))] = {
            "count": int(row.get("count") or 0),
            "revenue": money(row.get("revenue")),
        }

    invoices_by_school = defaultdict(lambda: {"count": 0, "outstanding": 0})
    async for row in db.platform_invoices.aggregate([
        {"$match": {"school_id": {"$in": school_ids}}},
        {"$group": {
            "_id": "$school_id",
            "count": {"$sum": 1},
            "outstanding": {
                "$sum": {
                    "$cond": [
                        {"$in": ["$status", ["pending", "overdue"]]},
                        {"$ifNull": ["$amount", 0]},
                        0,
                    ]
                }
            },
        }},
    ]):
        invoices_by_school[str(row.get("_id"))] = {
            "count": int(row.get("count") or 0),
            "outstanding": money(row.get("outstanding")),
        }

    schools = [
        serialize_school_summary(
            school,
            users_by_school[str(school.get("id") or school.get("_id"))],
            students_by_school[str(school.get("id") or school.get("_id"))],
            payments_by_school[str(school.get("id") or school.get("_id"))],
            invoices_by_school[str(school.get("id") or school.get("_id"))],
        )
        for school in school_docs
    ]
    return {
        "count": len(schools),
        "total": total,
        "page": page,
        "limit": limit,
        "pages": max(1, (total + limit - 1) // limit),
        "schools": schools,
    }


@router.get("/schools/pending")
async def get_pending_schools(user=Depends(require_super_admin)):
    schools_response = await get_all_schools(page=1, limit=200, user=user)
    schools = [
        school
        for school in schools_response["schools"]
        if school.get("approval_status") == "pending"
    ]
    return {"count": len(schools), "schools": schools}


@router.get("/schools/{school_id}")
async def get_school_detail(school_id: str, user=Depends(require_super_admin)):
    school = await db.schools.find_one(active_school_lookup(school_id))
    if not school:
        raise HTTPException(status_code=404, detail="School not found")

    school_id = str(school.get("id") or school_id)
    users, students, staff, payments, invoices, tickets, logs, storage = await asyncio.gather(
        db.users.find({"school_id": school_id}, {"_id": 0, "password_hash": 0, "temporary_password": 0}).to_list(500),
        db.students.count_documents({"school_id": school_id}),
        db.users.count_documents({"school_id": school_id, "role": {"$in": ["teacher", "finance", "secretary"]}}),
        db.payments.find({"school_id": school_id}, {"_id": 0}).sort("created_at", -1).limit(100).to_list(100),
        db.platform_invoices.find({"school_id": school_id}, {"_id": 0}).sort("created_at", -1).limit(100).to_list(100),
        db.support_tickets.find({"school_id": school_id}, {"_id": 0}).sort("created_at", -1).limit(100).to_list(100),
        db.audit_logs.find({"school_id": school_id}, {"_id": 0}).sort("timestamp", -1).limit(100).to_list(100),
        asyncio.to_thread(upload_storage_usage, school_id),
    )
    today = datetime.now(timezone.utc).date().isoformat()
    audit_today = sum(1 for log in logs if is_today(log.get("timestamp"), today))

    detail = serialize_school_summary(school, users, students, payments, invoices)
    detail.update({
        "general_information": serialize_doc(school),
        "branding": {
            "logo_url": school.get("logo_url"),
            "motto": school.get("motto"),
            "theme": school.get("theme") or {},
        },
        "subscription": {
            "plan": school.get("subscription_plan") or "standard",
            "status": school.get("subscription_status"),
            "amount": school.get("subscription_amount", 2000),
            "billing_day": school.get("billing_day"),
        },
        "students": {"count": students},
        "staff": {"count": staff, "users": users},
        "finance_summary": {
            "paid": sum(money(p.get("amount")) for p in payments if p.get("status") in {"paid", "completed", "approved"}),
            "outstanding": sum(money(i.get("amount")) for i in invoices if i.get("status") in {"pending", "overdue"}),
            "payments": payments,
            "invoices": invoices,
        },
        "system_usage": {"active_users": sum(1 for u in users if u.get("is_active") is not False)},
        "login_history": [u for u in users if u.get("last_login")],
        "api_usage": {"requests_today": audit_today, "recent_events": len(logs)},
        "storage_usage": storage,
        "support_tickets": tickets,
        "audit_logs": logs,
        "recent_activities": logs[:10],
    })
    return detail


@router.delete("/schools/{school_id}")
async def delete_school(school_id: str, user=Depends(require_super_admin)):
    school = await db.schools.find_one(active_school_lookup(school_id))
    if not school:
        raise HTTPException(status_code=404, detail="School not found")

    canonical_id = str(school.get("id") or school_id)
    if not canonical_id:
        raise HTTPException(status_code=409, detail="School record has no stable tenant ID")
    now = now_iso()
    deletion_id = str(ObjectId())

    # Soft deletion keeps tenant records consistently attached and recoverable,
    # while immediately revoking access. The tombstone is excluded everywhere
    # in platform school management by school_lookup/get_all_schools.
    await db.schools.update_one(
        {"_id": school["_id"], "deleted_at": {"$exists": False}},
        {"$set": {
            "deleted_at": now,
            "deleted_by": user.get("user_id"),
            "deletion_id": deletion_id,
            "status": "deleted",
            "approval_status": "deleted",
            "subscription_status": "inactive",
            "is_active": False,
            "updated_at": now,
        }},
    )
    users_result = await db.users.update_many(
        {"school_id": canonical_id},
        {"$set": {
            "is_active": False,
            "is_blocked": True,
            "status": "school_deleted",
            "auth_revoked_at": now,
            "updated_at": now,
        }},
    )
    await db.auth_sessions.update_many(
        {"school_id": canonical_id, "revoked": {"$ne": True}},
        {"$set": {"revoked": True, "revoked_at": now, "revocation_reason": "school_deleted"}},
    )
    await log_action(
        "school_deleted",
        user,
        canonical_id,
        {"deletion_id": deletion_id, "users_disabled": getattr(users_result, "modified_count", 0)},
    )
    return {
        "message": "School deleted and tenant access revoked",
        "school_id": canonical_id,
        "deletion_id": deletion_id,
        "retention": "Tenant data is retained under the deleted school tombstone for safe recovery and controlled cleanup.",
    }


@router.patch("/schools/{school_id}/approve")
async def approve_school(school_id: str, user=Depends(require_super_admin)):
    school = await db.schools.find_one(active_school_lookup(school_id))
    if not school:
        raise HTTPException(status_code=404, detail="School not found")
    canonical_id = str(school.get("id") or school_id)
    now = now_iso()
    await db.schools.update_one(
        {"_id": school["_id"]},
        {"$set": {
            "approval_status": "approved",
            "status": "active",
            "is_active": True,
            "subscription_status": "active",
            "payment_status": "paid",
            "payment_verification_status": "verified",
            "approved_at": now,
            "approved_by": user.get("user_id"),
            "updated_at": now,
        }}
    )
    await db.users.update_many(
        {"school_id": canonical_id},
        {"$set": {"approval_status": "approved", "is_active": True, "is_suspended": False, "updated_at": now}}
    )
    await db.platform_invoices.update_many(
        {"school_id": canonical_id, "invoice_type": "installation"},
        {"$set": {"status": "paid", "paid_at": now, "updated_at": now}}
    )
    school_admins = await db.users.find(
        {"school_id": canonical_id, "role": "school_admin"},
        {"_id": 0},
    ).to_list(100)
    await dispatch_notifications(
        db,
        school_id=canonical_id,
        title="Smart M Hub school approved",
        message=f"{school.get('name') or 'Your school'} has been approved. Authorized users can now sign in.",
        recipients=school_admins,
        channels=["email", "sms"],
        event_type="school_approved",
        requested_by=user.get("user_id"),
    )
    await log_action("school_approved", user, canonical_id)
    return {"message": "School and users approved successfully"}


@router.patch("/schools/{school_id}/reject")
async def reject_school(school_id: str, user=Depends(require_super_admin)):
    school = await db.schools.find_one(active_school_lookup(school_id))
    if not school:
        raise HTTPException(status_code=404, detail="School not found")
    canonical_id = str(school.get("id") or school_id)
    now = now_iso()
    await db.schools.update_one(
        {"_id": school["_id"]},
        {"$set": {
            "approval_status": "rejected",
            "status": "rejected",
            "is_active": False,
            "subscription_status": "inactive",
            "payment_status": school.get("payment_status") or "pending",
            "rejected_at": now,
            "rejected_by": user.get("user_id"),
            "updated_at": now,
        }}
    )
    await db.users.update_many(
        {"school_id": canonical_id},
        {"$set": {"approval_status": "rejected", "is_active": False, "updated_at": now}}
    )
    school_admins = await db.users.find(
        {"school_id": canonical_id, "role": "school_admin"},
        {"_id": 0},
    ).to_list(100)
    await dispatch_notifications(
        db,
        school_id=canonical_id,
        title="Smart M Hub school registration rejected",
        message=f"{school.get('name') or 'Your school'} registration was rejected. Contact Smart M Hub support for assistance.",
        recipients=school_admins,
        channels=["email", "sms"],
        event_type="school_rejected",
        requested_by=user.get("user_id"),
    )
    await log_action("school_rejected", user, canonical_id)
    return {"message": "School registration rejected"}


@router.patch("/schools/{school_id}/suspend")
async def suspend_school(school_id: str, user=Depends(require_super_admin)):
    school = await db.schools.find_one(active_school_lookup(school_id))
    if not school:
        raise HTTPException(status_code=404, detail="School not found")
    canonical_id = str(school.get("id") or school_id)
    await db.schools.update_one({"_id": school["_id"]}, {"$set": {"status": "suspended", "is_active": False, "subscription_status": "suspended", "updated_at": now_iso()}})
    await log_action("school_suspended", user, canonical_id)
    return {"message": "School suspended"}


@router.patch("/schools/{school_id}/activate")
async def activate_school(school_id: str, user=Depends(require_super_admin)):
    school = await db.schools.find_one(active_school_lookup(school_id))
    if not school:
        raise HTTPException(status_code=404, detail="School not found")
    canonical_id = str(school.get("id") or school_id)
    await db.schools.update_one({"_id": school["_id"]}, {"$set": {"approval_status": "approved", "status": "active", "is_active": True, "subscription_status": "active", "updated_at": now_iso()}})
    await log_action("school_activated", user, canonical_id)
    return {"message": "School activated"}


@router.patch("/schools/{school_id}/toggle")
async def toggle_school_status(school_id: str, user=Depends(require_super_admin)):
    school = await db.schools.find_one(active_school_lookup(school_id))
    if not school:
        raise HTTPException(status_code=404, detail="School not found")
    return await (suspend_school if school.get("is_active") else activate_school)(school_id, user)


@router.post("/schools/{school_id}/reset-password")
async def reset_school_admin_password(school_id: str, data: dict, user=Depends(require_super_admin)):
    school = await db.schools.find_one(active_school_lookup(school_id))
    if not school:
        raise HTTPException(status_code=404, detail="School not found")
    canonical_id = str(school.get("id") or school_id)
    password = str(data.get("password") or "").strip()
    if not password:
        raise HTTPException(status_code=400, detail="A new password is required")
    validate_password_strength(password)
    school_admin = await db.users.find_one({"school_id": canonical_id, "role": "school_admin"})
    result = await db.users.update_one(
        {"school_id": canonical_id, "role": "school_admin"},
        {"$set": {"password_hash": hash_password(password), "temporary_password": password, "updated_at": now_iso()}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="School admin not found")
    await dispatch_notifications(
        db,
        school_id=canonical_id,
        title="Smart M Hub password changed",
        message="Your Smart M Hub school administrator password was changed. If you did not expect this, contact Smart M Hub support immediately.",
        recipients=[school_admin] if school_admin else [],
        channels=["email", "sms"],
        event_type="school_admin_password_changed",
        requested_by=user.get("user_id"),
    )
    await log_action("school_admin_password_reset", user, canonical_id)
    return {"message": "Password reset", "temporary_password": password}


@router.get("/schools/{school_id}/users")
async def school_users(school_id: str, user=Depends(require_super_admin)):
    school = await db.schools.find_one(active_school_lookup(school_id))
    if not school:
        raise HTTPException(status_code=404, detail="School not found")
    canonical_id = str(school.get("id") or school_id)
    users = await db.users.find({"school_id": canonical_id}, {"_id": 0, "password_hash": 0, "temporary_password": 0}).to_list(1000)
    return {"count": len(users), "users": users}


@router.get("/payments/summary")
async def payment_summary(user=Depends(require_super_admin)):
    payments = await db.payments.find({}, {"_id": 0}).sort("created_at", -1).limit(500).to_list(500)
    invoices = await db.platform_invoices.find({}, {"_id": 0}).sort("created_at", -1).limit(500).to_list(500)
    return {
        "installation_fees": sum(money(i.get("amount")) for i in invoices if i.get("invoice_type") == "installation"),
        "monthly_subscriptions": sum(money(i.get("amount")) for i in invoices if i.get("invoice_type") == "subscription"),
        "pending_payments": sum(1 for i in invoices if i.get("status") == "pending"),
        "overdue_schools": await db.schools.count_documents({"subscription_status": "expired"}),
        "payment_history": payments,
        "invoices": invoices,
        "revenue_charts": monthly_buckets(payments + invoices),
        "totalPayments": len(payments) + len(invoices),
        "totalRevenue": sum(money(p.get("amount")) for p in payments if p.get("status") in {"paid", "completed", "approved"}) + sum(money(i.get("amount")) for i in invoices if i.get("status") == "paid"),
        "pendingPayments": sum(1 for p in payments if p.get("status") == "pending") + sum(1 for i in invoices if i.get("status") == "pending"),
    }


def monthly_buckets(records):
    buckets = {}
    for record in records:
        raw = str(record.get("created_at") or record.get("paid_at") or "")[:7] or "unknown"
        buckets.setdefault(raw, 0)
        buckets[raw] += money(record.get("amount"))
    return [{"month": key, "amount": value} for key, value in sorted(buckets.items())]


@router.get("/analytics")
async def analytics(user=Depends(require_super_admin)):
    schools = await db.schools.find({}, {"_id": 0}).to_list(5000)
    students = await db.students.find({}, {"_id": 0}).to_list(10000)
    users = await db.users.find({}, {"_id": 0}).to_list(10000)
    payments = await db.payments.find({}, {"_id": 0}).to_list(10000)
    invoices = await db.platform_invoices.find({}, {"_id": 0}).to_list(10000)
    attendance = await db.attendance_summaries.find({}, {"_id": 0}).to_list(10000)
    audit_logs = await db.audit_logs.find({}, {"_id": 0}).sort("timestamp", -1).limit(10000).to_list(10000)
    support_tickets = await db.support_tickets.find({}, {"_id": 0}).to_list(5000)

    school_activity = []
    for school in schools:
        school_id = school.get("id")
        school_activity.append({
            "id": school_id,
            "name": school.get("name"),
            "users": sum(1 for u in users if u.get("school_id") == school_id),
            "students": sum(1 for s in students if s.get("school_id") == school_id),
            "payments": sum(1 for p in payments if p.get("school_id") == school_id),
            "support_tickets": sum(1 for t in support_tickets if t.get("school_id") == school_id),
            "last_login": max([u.get("last_login") for u in users if u.get("school_id") == school_id and u.get("last_login")] or [None]),
        })

    return {
        "revenue": monthly_buckets(payments + invoices),
        "school_growth": monthly_count(schools),
        "student_growth": monthly_count(students),
        "user_growth": monthly_count(users),
        "monthly_registrations": monthly_count(schools),
        "payment_growth": monthly_count(payments),
        "invoice_growth": monthly_count(invoices),
        "attendance_summary": monthly_buckets([{"created_at": a.get("date"), "amount": a.get("count")} for a in attendance]),
        "audit_activity": monthly_count(audit_logs),
        "support_activity": monthly_count(support_tickets),
        "system_usage": {
            "users": len(users),
            "students": len(students),
            "schools": len(schools),
            "payments": len(payments),
            "invoices": len(invoices),
            "support_tickets": len(support_tickets),
            "audit_events": len(audit_logs),
            "storage": upload_storage_usage(),
        },
        "most_active_schools": sorted(school_activity, key=lambda x: (x["users"] + x["students"] + x["payments"] + x["support_tickets"]), reverse=True)[:10],
        "most_active_users": sorted(
            [{"name": u.get("full_name"), "email": u.get("email"), "role": u.get("role"), "school_id": u.get("school_id"), "last_login": u.get("last_login")} for u in users],
            key=lambda x: str(x.get("last_login") or ""),
            reverse=True
        )[:10],
        "status_breakdowns": {
            "schools": status_breakdown(schools, "status"),
            "subscriptions": status_breakdown(schools, "subscription_status"),
            "payments": status_breakdown(payments, "status"),
            "invoices": status_breakdown(invoices, "status"),
            "support": status_breakdown(support_tickets, "status"),
        },
    }


def monthly_count(records):
    buckets = {}
    for record in records:
        key = str(record.get("created_at") or "")[:7] or "unknown"
        buckets[key] = buckets.get(key, 0) + 1
    return [{"month": key, "count": value} for key, value in sorted(buckets.items())]


def status_breakdown(records, key):
    buckets = {}
    for record in records:
        status_value = str(record.get(key) or "unknown").lower()
        buckets[status_value] = buckets.get(status_value, 0) + 1
    return [{"status": key, "count": value} for key, value in sorted(buckets.items())]


@router.get("/support-tickets")
async def get_tickets(user=Depends(require_super_admin)):
    tickets = await db.support_tickets.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return tickets


@router.post("/support-tickets")
async def create_ticket(data: dict, user=Depends(require_super_admin)):
    ticket = {
        "id": str(ObjectId()),
        "school_id": data.get("school_id"),
        "subject": data.get("subject") or "Platform support",
        "message": data.get("message"),
        "priority": data.get("priority") or "normal",
        "status": "open",
        "assigned_to": data.get("assigned_to"),
        "replies": [],
        "internal_notes": [],
        "resolution_history": [],
        "created_at": now_iso(),
    }
    await db.support_tickets.insert_one(ticket)
    await log_action("platform_support_ticket_created", user, ticket.get("school_id"), {"ticket_id": ticket["id"], "priority": ticket["priority"]})
    return {"message": "Ticket created successfully", "ticket": serialize_doc(ticket)}


@router.patch("/support-tickets/{ticket_id}")
async def update_ticket(ticket_id: str, data: dict, user=Depends(require_super_admin)):
    update = {"updated_at": now_iso()}
    for field in ["status", "priority", "assigned_to"]:
        if field in data:
            update[field] = data[field]
    push = {}
    if data.get("reply"):
        push["replies"] = {"message": data["reply"], "by": user.get("email"), "created_at": now_iso()}
    if data.get("internal_note"):
        push["internal_notes"] = {"note": data["internal_note"], "by": user.get("email"), "created_at": now_iso()}
    if data.get("resolution"):
        push["resolution_history"] = {"resolution": data["resolution"], "by": user.get("email"), "created_at": now_iso()}
    operation = {"$set": update}
    if push:
        operation["$push"] = push
    await db.support_tickets.update_one({"$or": [{"id": ticket_id}, {"_id": ObjectId(ticket_id) if ObjectId.is_valid(ticket_id) else ticket_id}]}, operation)
    await log_action("platform_support_ticket_updated", user, metadata={"ticket_id": ticket_id, "fields": list(update.keys()), "appended": list(push.keys())})
    return {"message": "Ticket updated successfully"}


@router.get("/alerts")
async def system_alerts(user=Depends(require_super_admin)):
    alerts = []
    pending = await db.schools.count_documents({"approval_status": "pending"})
    expired = await db.schools.count_documents({"subscription_status": "expired"})
    failed = await db.payments.count_documents({"status": "failed"})
    if pending:
        alerts.append({"type": "warning", "message": f"{pending} schools pending approval"})
    if expired:
        alerts.append({"type": "critical", "message": f"{expired} schools have expired subscriptions"})
    if failed:
        alerts.append({"type": "warning", "message": f"{failed} failed payments detected"})
    return alerts


@router.get("/platform-control")
async def platform_control(user=Depends(require_super_admin)):
    settings = await db.platform_settings.find_one({}, {"_id": 0}) or {}
    return {
        "platform_settings": settings,
        "subscription_plans": settings.get("subscription_plans", [{"name": "Standard", "monthly_amount": 2000, "installation_fee": 5000}]),
        "pricing": {"installation_fee": 5000, "monthly_subscription": 2000},
        "global_announcements": await db.global_announcements.find({}, {"_id": 0}).sort("created_at", -1).to_list(100),
        "maintenance_mode": bool(settings.get("maintenance_mode", False)),
        "system_configuration": settings.get("system_configuration", {}),
        "feature_flags": settings.get("feature_flags", {}),
    }


@router.patch("/platform-control")
async def update_platform_control(data: dict, user=Depends(require_super_admin)):
    await db.platform_settings.update_one({}, {"$set": {**data, "updated_at": now_iso()}}, upsert=True)
    announcement = str(data.get("latest_announcement") or "").strip()
    if announcement:
        await db.global_announcements.insert_one({
            "id": str(ObjectId()),
            "title": data.get("announcement_title") or "Platform Announcement",
            "message": announcement,
            "status": "active",
            "created_by": user.get("user_id"),
            "created_at": now_iso(),
        })
    await log_action("platform_settings_updated", user)
    return {"message": "Platform settings updated"}


@router.patch("/schools/{school_id}/subscription")
async def update_subscription(school_id: str, data: dict, user=Depends(require_super_admin)):
    school = await db.schools.find_one(active_school_lookup(school_id))
    if not school:
        raise HTTPException(status_code=404, detail="School not found")
    await db.schools.update_one(
        {"_id": school["_id"]},
        {"$set": {"subscription_status": data.get("status"), "subscription_plan": data.get("plan"), "updated_at": now_iso()}}
    )
    await log_action("subscription_updated", user, str(school.get("id") or school_id), data)
    return {"message": "Subscription updated"}


@router.patch("/invoices/{invoice_id}/mark-paid")
async def mark_invoice_paid(invoice_id: str, data: dict = None, user=Depends(require_super_admin)):
    invoice_filter = {"$or": [{"id": invoice_id}]}
    if ObjectId.is_valid(invoice_id):
        invoice_filter["$or"].append({"_id": ObjectId(invoice_id)})
    invoice = await db.platform_invoices.find_one(invoice_filter)
    if not invoice:
        raise HTTPException(status_code=404, detail="Invoice not found")

    now = now_iso()
    reference = (data or {}).get("reference")
    await db.platform_invoices.update_one(
        {"_id": invoice["_id"]},
        {"$set": {
            "status": "paid",
            "paid_at": now,
            "payment_reference": reference,
            "updated_at": now,
        }}
    )

    school_id = invoice.get("school_id")
    if invoice.get("invoice_type") == "subscription" and school_id:
        await db.schools.update_one(
            active_school_lookup(str(school_id)),
            {"$set": {
                "subscription_status": "active",
                "payment_status": "paid",
                "status": "active",
                "is_active": True,
                "updated_at": now,
            }}
        )

    await log_action("invoice_marked_paid", user, school_id, {"invoice_id": invoice_id, "reference": reference})
    return {"message": "Invoice marked paid"}


@router.post("/run-billing-check")
async def billing_check(user=Depends(require_super_admin)):
    today = datetime.now(timezone.utc).date()
    created_invoices = 0
    reminders_created = 0
    overdue_invoices = 0
    expired_schools = 0

    schools = await db.schools.find({
        "approval_status": "approved",
        "subscription_status": {"$in": ["active", "trial", "expired"]},
    }).to_list(5000)

    for school in schools:
        school_id = str(school.get("id") or school.get("_id"))
        due_date = parse_date(school.get("next_billing_date")) or billing_due_date(today, school.get("billing_day"))
        days_until_due = (due_date - today).days

        should_have_invoice = days_until_due <= 5 or str(school.get("subscription_status")).lower() == "expired"
        if not should_have_invoice:
            continue

        invoice, created = await ensure_subscription_invoice(school, due_date)
        if created:
            created_invoices += 1

        invoice_due_date = parse_date(invoice.get("due_date")) or due_date
        invoice_status = str(invoice.get("status") or "pending").lower()
        invoice_days_until_due = (invoice_due_date - today).days

        if invoice_status == "pending" and 0 <= invoice_days_until_due <= 5:
            reminder_type = "due_today" if invoice_days_until_due == 0 else "five_day"
            if await create_subscription_reminder(school, invoice, reminder_type, invoice_days_until_due):
                reminders_created += 1

        if invoice_status in {"pending", "overdue"} and invoice_due_date < today:
            if invoice_status != "overdue":
                await db.platform_invoices.update_one(
                    {"id": invoice.get("id")},
                    {"$set": {"status": "overdue", "updated_at": now_iso()}}
                )
                overdue_invoices += 1
            school_update = await db.schools.update_one(
                active_school_lookup(school_id),
                {"$set": {
                    "subscription_status": "expired",
                    "payment_status": "overdue",
                    "status": "subscription_expired",
                    "is_active": False,
                    "updated_at": now_iso(),
                }}
            )
            if school_update.modified_count:
                expired_schools += 1

    disabled_existing = await db.schools.update_many(
        {"subscription_status": "expired"},
        {"$set": {"is_active": False, "status": "subscription_expired", "updated_at": now_iso()}}
    )

    summary = {
        "created_invoices": created_invoices,
        "reminders_created": reminders_created,
        "overdue_invoices": overdue_invoices,
        "expired_schools": expired_schools,
        "disabled_schools": disabled_existing.modified_count,
    }
    await log_action("billing_check_completed", user, metadata=summary)
    return {"message": "Billing check completed", **summary}


@router.get("/audit-logs")
async def get_audit_logs(user=Depends(require_super_admin)):
    logs = await db.audit_logs.find({}, {"_id": 0}).sort("timestamp", -1).limit(500).to_list(500)
    return logs


@router.get("/diagnostics")
async def get_diagnostics(user=Depends(require_super_admin)):
    action_filter = {
        "$or": [
            {"action": {"$regex": "error", "$options": "i"}},
            {"action": {"$regex": "failed", "$options": "i"}},
            {"action": {"$regex": "blocked", "$options": "i"}},
            {"metadata.severity": {"$in": ["high", "critical"]}},
        ]
    }
    audit_errors = await db.audit_logs.find(action_filter, {"_id": 0}).sort("timestamp", -1).limit(200).to_list(200)
    frontend_errors = await db.diagnostics.find({}, {"_id": 0}).sort("timestamp", -1).limit(200).to_list(200)
    notes = await db.diagnostic_notes.find({}, {"_id": 0}).to_list(500)
    note_map = {n.get("source_id"): n for n in notes}

    records = []
    for error in frontend_errors + audit_errors:
        source_id = str(error.get("id") or error.get("_id"))
        records.append(diagnostic_from_error(error, note_map.get(source_id)))

    records.sort(key=lambda item: str(item.get("timestamp") or ""), reverse=True)
    return {"success": True, "data": records[:250], "count": min(len(records), 250)}


@router.patch("/diagnostics/{source_id}")
async def update_diagnostic_status(source_id: str, payload: dict, user=Depends(require_super_admin)):
    diagnostic_status = str(payload.get("status") or "").strip().lower()
    if diagnostic_status not in {"new", "reviewed", "fixed", "ignored"}:
        raise HTTPException(status_code=400, detail="Status must be new, reviewed, fixed, or ignored")
    note = {
        "source_id": source_id,
        "status": diagnostic_status,
        "fix_notes": str(payload.get("fix_notes") or "").strip(),
        "reviewed_by": user.get("email"),
        "reviewed_at": now_iso(),
        "updated_at": now_iso(),
    }
    await db.diagnostic_notes.update_one(
        {"source_id": source_id},
        {"$set": note, "$setOnInsert": {"id": str(ObjectId()), "created_at": now_iso()}},
        upsert=True,
    )
    await log_action("diagnostic_reviewed", user, metadata={"source_id": source_id, "status": diagnostic_status})
    return {"success": True, "message": "Diagnostic updated"}


@router.post("/diagnostics/report")
async def report_diagnostic(payload: dict, user=Depends(require_super_admin)):
    record = {
        "id": str(ObjectId()),
        "action": payload.get("action") or "frontend_error",
        "performed_by": user.get("email"),
        "user_id": user.get("user_id"),
        "school_id": payload.get("school_id"),
        "metadata": {
            "message": payload.get("message"),
            "severity": payload.get("severity") or "medium",
            "route": payload.get("route"),
            "component": payload.get("component"),
            "affected_file": payload.get("affected_file"),
            "stack_trace": payload.get("stack_trace"),
            "suggested_fix": payload.get("suggested_fix"),
        },
        "timestamp": now_iso(),
    }
    await db.diagnostics.insert_one(record)
    await log_action("diagnostic_reported", user, payload.get("school_id"), {"diagnostic_id": record["id"]})
    return {"success": True, "id": record["id"]}


@router.post("/support-notices")
async def create_support_notice(payload: dict, user=Depends(require_super_admin)):
    school_id = str(payload.get("school_id") or "").strip()
    if not school_id:
        raise HTTPException(status_code=400, detail="school_id is required")
    school = await db.schools.find_one(active_school_lookup(school_id))
    if not school:
        raise HTTPException(status_code=404, detail="School not found")
    notice = {
        "id": str(ObjectId()),
        "school_id": str(school.get("id") or school.get("_id")),
        "school_name": school.get("name"),
        "title": str(payload.get("title") or "").strip(),
        "message": str(payload.get("message") or "").strip(),
        "notice_type": payload.get("notice_type") or "support",
        "severity": payload.get("severity") or "info",
        "read_by": [],
        "created_by": user.get("email"),
        "created_at": now_iso(),
        "updated_at": now_iso(),
    }
    if not notice["title"] or not notice["message"]:
        raise HTTPException(status_code=400, detail="Title and message are required")
    await db.support_notices.insert_one(notice)
    await log_action("support_notice_created", user, notice["school_id"], {"notice_id": notice["id"]})
    return {"success": True, "notice": serialize_doc(notice)}
