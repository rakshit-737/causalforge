import pytest

from causalforge.config import Settings, redacted_url


def test_local_defaults_are_lab_safe() -> None:
    settings = Settings()

    assert settings.environment == "local"
    assert settings.lab_only is True
    assert settings.external_network_enabled is False
    assert settings.database_url.startswith("sqlite:")
    assert settings.auto_create_schema is False


def test_local_settings_reject_external_network_access() -> None:
    with pytest.raises(ValueError, match="external network access"):
        Settings(environment="lab", external_network_enabled=True)


def test_production_settings_reject_auto_schema_creation() -> None:
    with pytest.raises(ValueError, match="auto_create_schema"):
        Settings(
            environment="production",
            auto_create_schema=True,
            lab_only=False,
        )


def test_redacted_url_removes_credentials_and_query_values() -> None:
    value = redacted_url("postgresql+psycopg://user:password@example.test:5432/db?sslmode=require")

    assert value == "postgresql+psycopg://example.test:5432/db"
    assert "password" not in value
    assert "sslmode" not in value


def test_settings_repr_does_not_include_database_credentials() -> None:
    settings = Settings(
        database_url="postgresql+psycopg://cf_user:do-not-log@localhost:5432/causalforge"
    )

    assert "do-not-log" not in repr(settings)
    assert "cf_user" not in repr(settings)
