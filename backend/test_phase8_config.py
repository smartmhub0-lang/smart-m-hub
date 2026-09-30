import pytest

from config import ConfigurationError, load_secret_file_env, normalize_mongo_url, validate_environment


def test_development_environment_allows_local_defaults(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.delenv("MONGO_URL", raising=False)
    monkeypatch.delenv("SECRET_KEY", raising=False)

    validate_environment()


def test_production_environment_requires_core_settings(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    for name in ["MONGO_URL", "DB_NAME", "SECRET_KEY", "FRONTEND_URL", "ALLOWED_ORIGINS", "CORS_ORIGINS"]:
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(ConfigurationError) as exc_info:
        validate_environment()

    message = str(exc_info.value)
    assert "MONGO_URL is required" in message
    assert "SECRET_KEY is required" in message
    assert "FRONTEND_URL is required" in message


def test_secret_file_env_loads_value(monkeypatch):
    secret_file = __import__("pathlib").Path(__file__).with_name("_phase8_secret.tmp")
    try:
        secret_file.write_text("from-file", encoding="utf-8")
        monkeypatch.delenv("SECRET_KEY", raising=False)
        monkeypatch.setenv("SECRET_KEY_FILE", str(secret_file))

        load_secret_file_env(["SECRET_KEY"])

        assert __import__("os").getenv("SECRET_KEY") == "from-file"
    finally:
        if secret_file.exists():
            secret_file.unlink()


def test_normalize_mongo_url_encodes_atlas_credentials_and_sets_auth_source():
    uri = "mongodb+srv://user:p@ss/word@cluster.mongodb.net/smart_m_hub?retryWrites=true"

    normalized = normalize_mongo_url(uri)

    assert normalized == (
        "mongodb+srv://user:p%40ss%2Fword@cluster.mongodb.net/"
        "?retryWrites=true&authSource=admin"
    )


def test_normalize_mongo_url_leaves_non_atlas_urls_unchanged():
    uri = "mongodb://localhost:27017"

    assert normalize_mongo_url(uri) == uri
