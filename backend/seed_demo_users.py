from datetime import datetime, timezone
from pricing import ACTIVATION_FEE_KES
import os
import secrets
import string
from pymongo import MongoClient
from auth import hash_password


client = MongoClient(os.getenv("MONGO_URL", "mongodb://localhost:27017"))
db = client[os.getenv("DB_NAME", "smart_m_hub")]


def demo_password(env_name):
    configured = os.getenv(env_name)
    if configured:
        return configured
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(14))

now = datetime.now(timezone.utc)
demo_school_id = "demo-school"
demo_school_code = "SMH-KE-000001"
frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000").rstrip("/")
existing_demo_school = db.schools.find_one({"school_code": demo_school_code})
if existing_demo_school:
    demo_school_id = existing_demo_school.get("id") or demo_school_id

db.schools.update_one(
    {"$or": [{"id": demo_school_id}, {"school_code": demo_school_code}]},
    {
        "$set": {
            "id": demo_school_id,
            "name": "Demo School",
            "slug": "demo-school",
            "school_code": demo_school_code,
            "login_link": f"{frontend_url}/login?school={demo_school_code}",
            "invite_code": "DEMO2026",
            "invite_link": f"{frontend_url}/join/demo-school-DEMO2026",
            "address": "Demo Campus",
            "phone": "+254700000000",
            "email": "admin@demo.com",
            "school_type": "primary",
            "school_classification": "private",
            "operation_type": "day",
            "boarding_enabled": False,
            "status": "active",
            "is_active": True,
            "approval_status": "approved",
            "subscription_status": "active",
            "subscription_plan": "standard",
            "subscription_amount": 2000,
            "payment_status": "paid",
            "billing_day": now.day,
            "theme": {"primary": "#10B981", "secondary": "#0F172A"},
            "approved_at": now,
            "updated_at": now,
        },
        "$setOnInsert": {"created_at": now},
    },
    upsert=True,
)

users = [
    {"email": "admin@demo.com", "password": demo_password("DEMO_ADMIN_PASSWORD"), "role": "school_admin", "full_name": "Demo School Admin", "school_id": demo_school_id},
    {"email": "secretary@demo.com", "password": demo_password("DEMO_SECRETARY_PASSWORD"), "role": "secretary", "full_name": "Demo Secretary", "school_id": demo_school_id},
    {"email": "finance@demo.com", "password": demo_password("DEMO_FINANCE_PASSWORD"), "role": "finance", "full_name": "Demo Finance Officer", "school_id": demo_school_id},
    {"email": "teacher@demo.com", "password": demo_password("DEMO_TEACHER_PASSWORD"), "role": "teacher", "full_name": "Demo Teacher", "school_id": demo_school_id},
    {"email": "student@demo.com", "password": demo_password("DEMO_STUDENT_PASSWORD"), "role": "student", "full_name": "Demo Student", "school_id": demo_school_id},
]

for u in users:
    db.users.update_one(
        {"email": u["email"]},
        {
            "$set": {
                "email": u["email"],
                "full_name": u["full_name"],
                "password_hash": hash_password(u["password"]),
                "role": u["role"],
                "school_id": u["school_id"],
                "school_name": "Demo School",
                "approval_status": "approved",
                "is_active": True,
                "is_suspended": False,
                "updated_at": now,
            },
            "$setOnInsert": {"id": f"demo-{u['role']}", "created_at": now},
        },
        upsert=True,
    )
    print(f"{u['role']} demo user: {u['email']} / {u['password']}")

db.platform_invoices.update_one(
    {"school_id": demo_school_id, "invoice_type": {"$in": ["activation", "installation"]}},
    {
        "$set": {
            "school_id": demo_school_id,
            "school_name": "Demo School",
            "invoice_type": "activation",
            "invoice_number": f"INV-{demo_school_code}-DEMO",
            "amount": ACTIVATION_FEE_KES,
            "currency": "KES",
            "status": "paid",
            "paid_at": now,
            "updated_at": now,
        },
        "$setOnInsert": {"id": "demo-installation-invoice", "created_at": now},
    },
    upsert=True,
)

print("DONE: demo school approved and demo users activated")
