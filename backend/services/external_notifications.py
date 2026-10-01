from __future__ import annotations

import asyncio
import logging
import os
import re
import smtplib
import ssl
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any, Iterable, Optional

import httpx
from pymongo.errors import DuplicateKeyError
from services.job_queue import enqueue_job


logger = logging.getLogger("smart_m_hub.notifications")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def normalize_email(value: object) -> Optional[str]:
    email = str(value or "").strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        return None
    return email


def normalize_kenyan_phone(value: object) -> Optional[str]:
    raw = re.sub(r"[\s().-]", "", str(value or "").strip())
    if raw.startswith("00"):
        raw = "+" + raw[2:]
    if raw.startswith("0") and len(raw) == 10:
        raw = "+254" + raw[1:]
    elif raw.startswith("254") and len(raw) == 12:
        raw = "+" + raw
    if not re.fullmatch(r"\+254(?:7\d{8}|1\d{8})", raw):
        return None
    return raw


class NotificationProviderError(RuntimeError):
    pass


class EmailProvider(ABC):
    @abstractmethod
    async def send(self, *, to: str, subject: str, text: str) -> str:
        raise NotImplementedError


class SmsProvider(ABC):
    @abstractmethod
    async def send(self, *, to: str, text: str) -> str:
        raise NotImplementedError


class DisabledEmailProvider(EmailProvider):
    async def send(self, **_kwargs) -> str:
        raise NotificationProviderError("Email provider is not configured")


class DisabledSmsProvider(SmsProvider):
    async def send(self, **_kwargs) -> str:
        raise NotificationProviderError("SMS provider is not configured")


class SmtpEmailProvider(EmailProvider):
    async def send(self, *, to: str, subject: str, text: str) -> str:
        host = os.getenv("SMTP_HOST", "").strip()
        username = os.getenv("SMTP_USERNAME", "").strip()
        password = os.getenv("SMTP_PASSWORD", "")
        sender = os.getenv("EMAIL_FROM", "").strip()
        if not host or not sender:
            raise NotificationProviderError("SMTP_HOST and EMAIL_FROM are required")
        port = int(os.getenv("SMTP_PORT", "587"))
        use_tls = os.getenv("SMTP_USE_TLS", "true").lower() in {"1", "true", "yes"}
        use_ssl = os.getenv("SMTP_USE_SSL", "false").lower() in {"1", "true", "yes"}
        if use_tls and use_ssl:
            raise NotificationProviderError("SMTP_USE_TLS and SMTP_USE_SSL cannot both be enabled")
        if username and not password:
            raise NotificationProviderError("SMTP_PASSWORD is required when SMTP_USERNAME is configured")

        def deliver() -> None:
            message = EmailMessage()
            message["From"] = sender
            message["To"] = to
            message["Subject"] = subject
            message.set_content(text)
            smtp_client = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
            with smtp_client(host, port, timeout=20) as client:
                if use_tls:
                    client.starttls(context=ssl.create_default_context())
                if username:
                    client.login(username, password)
                client.send_message(message)

        await asyncio.to_thread(deliver)
        return "accepted"


class SendGridEmailProvider(EmailProvider):
    async def send(self, *, to: str, subject: str, text: str) -> str:
        api_key = os.getenv("EMAIL_API_KEY", "").strip()
        sender = os.getenv("EMAIL_FROM", "").strip()
        if not api_key or not sender:
            raise NotificationProviderError("EMAIL_API_KEY and EMAIL_FROM are required")
        endpoint = os.getenv("EMAIL_API_URL", "https://api.sendgrid.com/v3/mail/send").strip()
        payload = {
            "personalizations": [{"to": [{"email": to}]}],
            "from": {"email": sender},
            "subject": subject,
            "content": [{"type": "text/plain", "value": text}],
        }
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(endpoint, headers={"Authorization": f"Bearer {api_key}"}, json=payload)
        if response.status_code >= 300:
            raise NotificationProviderError(f"Email provider returned HTTP {response.status_code}")
        return response.headers.get("x-message-id", "accepted")


class AfricasTalkingSmsProvider(SmsProvider):
    async def send(self, *, to: str, text: str) -> str:
        api_key = os.getenv("SMS_API_KEY", "").strip()
        username = os.getenv("SMS_USERNAME", "").strip()
        if not api_key or not username:
            raise NotificationProviderError("SMS_API_KEY and SMS_USERNAME are required")
        endpoint = os.getenv("SMS_API_URL", "https://api.africastalking.com/version1/messaging").strip()
        form = {"username": username, "to": to, "message": text}
        sender_id = os.getenv("SMS_SENDER_ID", "").strip()
        if sender_id:
            form["from"] = sender_id
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(endpoint, headers={"apiKey": api_key, "Accept": "application/json"}, data=form)
        if response.status_code >= 300:
            raise NotificationProviderError(f"SMS provider returned HTTP {response.status_code}")
        return "accepted"


class GenericSmsProvider(SmsProvider):
    async def send(self, *, to: str, text: str) -> str:
        api_key = os.getenv("SMS_API_KEY", "").strip()
        endpoint = os.getenv("SMS_API_URL", "").strip()
        if not api_key or not endpoint:
            raise NotificationProviderError("SMS_API_KEY and SMS_API_URL are required")
        payload = {"to": to, "message": text, "sender_id": os.getenv("SMS_SENDER_ID", "").strip()}
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(endpoint, headers={"Authorization": f"Bearer {api_key}"}, json=payload)
        if response.status_code >= 300:
            raise NotificationProviderError(f"SMS provider returned HTTP {response.status_code}")
        return "accepted"


def get_email_provider() -> EmailProvider:
    provider = os.getenv("EMAIL_PROVIDER", "disabled").strip().lower()
    if provider == "smtp":
        return SmtpEmailProvider()
    if provider == "sendgrid":
        return SendGridEmailProvider()
    return DisabledEmailProvider()


def get_sms_provider() -> SmsProvider:
    provider = os.getenv("SMS_PROVIDER", "disabled").strip().lower()
    if provider in {"africastalking", "africas_talking"}:
        return AfricasTalkingSmsProvider()
    if provider == "generic":
        return GenericSmsProvider()
    return DisabledSmsProvider()


def super_admin_welcome_message() -> str:
    return (
        "Welcome to Smart M Hub Super Admin.\n\n"
        "You have been configured as the owner and Super Admin for Smart M Hub. "
        "Your account can manage platform-level operations, schools, and system settings.\n\n"
        "For security, keep your account credentials private and use the official Smart M Hub sign-in page.\n\n"
        "Regards,\nSmart M Hub"
    )


async def send_super_admin_welcome_email(db: Any, *, email: str) -> dict:
    """Send the configured owner welcome email once after provider acceptance.

    The durable event record prevents a service restart from resending an
    accepted message. Delivery is explicitly opt-in through an environment
    variable so configuring a provider alone does not send mail.
    """
    if os.getenv("SUPER_ADMIN_WELCOME_EMAIL_ENABLED", "false").lower() not in {"1", "true", "yes"}:
        return {"status": "disabled"}

    destination = normalize_email(email)
    if not destination:
        logger.warning("super_admin_welcome_email_skipped reason=invalid_recipient")
        return {"status": "invalid_recipient"}

    event_key = f"super_admin_welcome:{destination}"
    events = db.system_email_events
    existing = await events.find_one({"event_key": event_key})
    if existing:
        return {"status": "already_sent" if existing.get("status") == "sent" else "already_recorded"}

    now = now_utc()
    try:
        await events.insert_one({
            "event_key": event_key,
            "event_type": "super_admin_welcome",
            "destination": destination,
            "status": "sending",
            "created_at": now,
            "updated_at": now,
        })
    except DuplicateKeyError:
        return {"status": "already_recorded"}

    try:
        provider_reference = await get_email_provider().send(
            to=destination,
            subject="Welcome to Smart M Hub Super Admin",
            text=super_admin_welcome_message(),
        )
    except Exception as exc:
        await events.update_one(
            {"event_key": event_key},
            {"$set": {"status": "failed", "error_type": type(exc).__name__, "updated_at": now_utc()}},
        )
        logger.warning("super_admin_welcome_email_failed reason=%s", type(exc).__name__)
        return {"status": "failed"}

    await events.update_one(
        {"event_key": event_key},
        {"$set": {"status": "sent", "provider_reference": provider_reference, "sent_at": now_utc(), "updated_at": now_utc()}},
    )
    logger.info("super_admin_welcome_email_accepted")
    return {"status": "sent", "provider_reference": provider_reference}


async def dispatch_notifications(
    db: Any,
    *,
    school_id: str,
    title: str,
    message: str,
    recipients: Iterable[dict],
    channels: Iterable[str],
    event_type: str,
    requested_by: Optional[str] = None,
    force_delivery: bool = False,
) -> dict:
    selected_channels = [channel for channel in dict.fromkeys(channels) if channel in {"email", "sms"}]
    summary = {"total": 0, "succeeded": 0, "failed": 0, "skipped": 0, "channels": selected_channels}
    recipients = list(recipients)

    direct_limit = max(1, int(os.getenv("NOTIFICATION_DIRECT_DELIVERY_LIMIT", "20")))
    if not force_delivery and len(recipients) * max(len(selected_channels), 1) > direct_limit:
        queued = 0
        seen_addresses = set()
        for channel in selected_channels:
            channel_recipients = []
            for recipient in recipients:
                if str(recipient.get("school_id") or "") != str(school_id):
                    summary["skipped"] += 1
                    continue
                address = normalize_email(recipient.get("email")) if channel == "email" else normalize_kenyan_phone(recipient.get("phone"))
                if not address or (channel, address) in seen_addresses:
                    summary["skipped"] += 1
                    continue
                seen_addresses.add((channel, address))
                channel_recipients.append({
                    "id": recipient.get("id"),
                    "school_id": str(school_id),
                    "email": address if channel == "email" else None,
                    "phone": address if channel == "sms" else None,
                })
            for offset in range(0, len(channel_recipients), 100):
                batch = channel_recipients[offset:offset + 100]
                await enqueue_job(
                    db,
                    job_type="external_notification_delivery",
                    school_id=str(school_id),
                    payload={
                        "title": title,
                        "message": message,
                        "recipients": batch,
                        "channels": [channel],
                        "event_type": event_type,
                    },
                    requested_by=requested_by,
                )
                queued += len(batch)
        summary["total"] = queued
        summary["queued"] = queued
        return summary

    records = []
    email_provider = get_email_provider()
    sms_provider = get_sms_provider()
    seen = set()
    deliveries = []

    for recipient in recipients:
        if str(recipient.get("school_id") or "") != str(school_id):
            summary["skipped"] += len(selected_channels)
            logger.warning("notification_recipient_rejected school_scope_mismatch event=%s", event_type)
            continue
        for channel in selected_channels:
            address = normalize_email(recipient.get("email")) if channel == "email" else normalize_kenyan_phone(recipient.get("phone"))
            if not address or (channel, address) in seen:
                summary["skipped"] += 1
                continue
            seen.add((channel, address))
            summary["total"] += 1
            deliveries.append((recipient, channel, address))

    concurrency = max(1, min(int(os.getenv("NOTIFICATION_SEND_CONCURRENCY", "10")), 25))
    semaphore = asyncio.Semaphore(concurrency)

    async def deliver(recipient: dict, channel: str, address: str) -> dict:
            status = "sent"
            error = None
            provider_reference = None
            try:
                async with semaphore:
                    if channel == "email":
                        provider_reference = await email_provider.send(to=address, subject=title, text=message)
                    else:
                        provider_reference = await sms_provider.send(to=address, text=f"{title}: {message}")
                summary["succeeded"] += 1
                logger.info("notification_delivery_succeeded event=%s channel=%s school_id=%s", event_type, channel, school_id)
            except Exception as exc:
                status = "failed"
                error = str(exc)[:300]
                summary["failed"] += 1
                logger.warning("notification_delivery_failed event=%s channel=%s school_id=%s reason=%s", event_type, channel, school_id, type(exc).__name__)
            return {
                "id": str(uuid.uuid4()), "school_id": str(school_id), "event_type": event_type,
                "recipient_id": recipient.get("id"), "channel": channel, "destination": address,
                "status": status, "provider_reference": provider_reference, "error": error,
                "requested_by": requested_by, "created_at": now_utc(), "updated_at": now_utc(),
            }

    if deliveries:
        records = await asyncio.gather(*(deliver(recipient, channel, address) for recipient, channel, address in deliveries))
    if records:
        try:
            await db.notification_deliveries.insert_many(records)
        except Exception as exc:
            logger.warning("notification_delivery_log_failed event=%s reason=%s", event_type, type(exc).__name__)
    return summary


async def resolve_announcement_recipients(db: Any, *, school_id: str, announcement: dict) -> list[dict]:
    audience = str(announcement.get("target_audience") or "all").lower()
    users = []
    students = []
    if audience in {"all", "staff", "parents", "specific_staff"}:
        user_query: dict = {"school_id": school_id, "approval_status": "approved", "is_active": True}
        if audience == "staff":
            user_query["role"] = {"$in": ["school_admin", "teacher", "finance", "secretary", "supporting_staff"]}
        elif audience == "parents":
            user_query["role"] = "parent"
        elif audience == "specific_staff":
            user_query["id"] = {"$in": [str(value) for value in announcement.get("target_staff_user_ids") or []]}
        users = await db.users.find(user_query, {"_id": 0}).to_list(1000)
    if audience in {"all", "students", "parents", "class", "specific_students"}:
        student_query: dict = {"school_id": school_id, "approval_status": "approved"}
        if audience == "class":
            student_query["class_name"] = announcement.get("target_class")
        elif audience == "specific_students":
            targets = [str(value) for value in announcement.get("target_student_ids") or []]
            student_query["$or"] = [{"id": {"$in": targets}}, {"admission_number": {"$in": targets}}]
        students = await db.students.find(student_query, {"_id": 0}).to_list(2000)

    recipients = [{"id": user.get("id"), "school_id": school_id, "email": user.get("email"), "phone": user.get("phone")} for user in users]
    for student in students:
        recipients.extend([
            {"id": f"{student.get('id')}:guardian1", "school_id": school_id, "email": student.get("guardian_email"), "phone": student.get("guardian_phone")},
            {"id": f"{student.get('id')}:guardian2", "school_id": school_id, "email": student.get("secondary_guardian_email"), "phone": student.get("secondary_guardian_phone")},
        ])
    return recipients


def student_guardian_recipients(student: Optional[dict], *, school_id: str) -> list[dict]:
    if not student:
        return []
    student_id = student.get("id") or student.get("_id")
    return [
        {
            "id": f"{student_id}:guardian1",
            "school_id": str(school_id),
            "email": student.get("guardian_email"),
            "phone": student.get("guardian_phone"),
        },
        {
            "id": f"{student_id}:guardian2",
            "school_id": str(school_id),
            "email": student.get("secondary_guardian_email"),
            "phone": student.get("secondary_guardian_phone"),
        },
    ]


async def resolve_student_guardians(db: Any, *, school_id: str, item: Optional[dict]) -> list[dict]:
    item = item or {}
    if item.get("guardian_email") or item.get("guardian_phone") or item.get("secondary_guardian_email") or item.get("secondary_guardian_phone"):
        return student_guardian_recipients(item, school_id=school_id)
    student_id = item.get("student_id")
    admission_number = item.get("admission_number")
    conditions = []
    if student_id:
        conditions.append({"id": str(student_id)})
    if admission_number:
        conditions.append({"admission_number": str(admission_number)})
    if not conditions:
        return []
    student = await db.students.find_one({"school_id": str(school_id), "$or": conditions})
    return student_guardian_recipients(student, school_id=school_id)
