from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit


class ConfigurationError(RuntimeError):
    pass


def load_secret_file_env(names: Iterable[str]) -> None:
    for name in names:
        if os.getenv(name):
            continue
        file_name = f"{name}_FILE"
        secret_path = os.getenv(file_name)
        if not secret_path:
            continue
        path = Path(secret_path)
        if not path.exists():
            raise ConfigurationError(f"{file_name} points to a missing file: {secret_path}")
        os.environ[name] = path.read_text(encoding="utf-8").strip()


def current_env() -> str:
    return os.getenv("APP_ENV", os.getenv("ENV", "development")).lower()


def normalize_mongo_url(value: str) -> str:
    """Prepare an Atlas URI without placing credentials or the app DB in code.

    Atlas database users authenticate against ``admin``.  Environment values are
    sometimes pasted from connection strings with reserved password characters
    left unescaped, so encode only the user-info portion before Motor receives it.
    The application database remains controlled by ``DB_NAME``.
    """
    mongo_url = value.strip()
    if not mongo_url.lower().startswith("mongodb+srv://"):
        return mongo_url

    scheme, remainder = mongo_url.split("://", 1)
    user_info, separator, host_and_path = remainder.rpartition("@")
    encoded_user_info = ""
    if separator and ":" in user_info:
        username, password = user_info.split(":", 1)
        encoded_user_info = f"{quote(unquote(username), safe='')}:{quote(unquote(password), safe='')}@"
    else:
        host_and_path = remainder

    parsed = urlsplit(f"{scheme}://{host_and_path}")
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query["authSource"] = "admin"
    return urlunsplit((scheme, f"{encoded_user_info}{parsed.netloc}", "/", urlencode(query), ""))


def require_env(name: str, errors: list[str]) -> Optional[str]:
    value = os.getenv(name)
    if not value or not value.strip():
        errors.append(f"{name} is required")
        return None
    return value.strip()


def validate_environment() -> None:
    env = current_env()
    errors: list[str] = []

    if env in {"production", "prod"}:
        require_env("MONGO_URL", errors)
        require_env("DB_NAME", errors)
        secret_key = require_env("SECRET_KEY", errors)
        require_env("FRONTEND_URL", errors)
        require_env("SUPER_ADMIN_EMAIL", errors)
        require_env("SUPER_ADMIN_PASSWORD", errors)
        if not (os.getenv("ALLOWED_ORIGINS") or os.getenv("CORS_ORIGINS") or os.getenv("ALLOWED_ORIGIN_REGEX") or os.getenv("CORS_ORIGIN_REGEX")):
            errors.append("ALLOWED_ORIGINS/CORS_ORIGINS or ALLOWED_ORIGIN_REGEX/CORS_ORIGIN_REGEX is required")
        if secret_key and len(secret_key) < 32:
            errors.append("SECRET_KEY must be at least 32 characters in production")

    storage_backend = os.getenv("STORAGE_BACKEND", "local").lower()
    if storage_backend == "s3":
        for name in ["S3_BUCKET", "AWS_REGION"]:
            require_env(name, errors)

    if errors:
        raise ConfigurationError("Invalid Smart M Hub configuration: " + "; ".join(errors))
