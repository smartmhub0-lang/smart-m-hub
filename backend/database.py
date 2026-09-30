from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

from config import load_secret_file_env, normalize_mongo_url, validate_environment


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")
load_secret_file_env(["SECRET_KEY", "MONGO_URL", "SUPER_ADMIN_EMAIL", "SUPER_ADMIN_PASSWORD"])
validate_environment()

APP_ENV = os.getenv("APP_ENV", os.getenv("ENV", "development")).lower()
MONGO_URL = os.getenv("MONGO_URL")
if not MONGO_URL:
    if APP_ENV in {"production", "prod"}:
        raise RuntimeError("MONGO_URL must be set in production")
    MONGO_URL = "mongodb://localhost:27017"
else:
    MONGO_URL = normalize_mongo_url(MONGO_URL)

DB_NAME = str(os.getenv("DB_NAME", "smart_m_hub") or "").strip()
if not DB_NAME:
    raise RuntimeError("DB_NAME must be set")


def mongo_client_options() -> dict:
    return {
        "appname": os.getenv("MONGO_APP_NAME", "smart-m-hub-api"),
        "maxPoolSize": int(os.getenv("MONGO_MAX_POOL_SIZE", "50")),
        "minPoolSize": int(os.getenv("MONGO_MIN_POOL_SIZE", "0")),
        "maxIdleTimeMS": int(os.getenv("MONGO_MAX_IDLE_TIME_MS", "60000")),
        "waitQueueTimeoutMS": int(os.getenv("MONGO_WAIT_QUEUE_TIMEOUT_MS", "5000")),
        "serverSelectionTimeoutMS": int(os.getenv("MONGO_SERVER_SELECTION_TIMEOUT_MS", "5000")),
        "connectTimeoutMS": int(os.getenv("MONGO_CONNECT_TIMEOUT_MS", "10000")),
        "socketTimeoutMS": int(os.getenv("MONGO_SOCKET_TIMEOUT_MS", "20000")),
        "retryReads": True,
        "retryWrites": True,
    }


client = AsyncIOMotorClient(MONGO_URL, **mongo_client_options())
db = client[DB_NAME]
