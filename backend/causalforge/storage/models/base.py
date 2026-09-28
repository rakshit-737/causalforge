"""SQLAlchemy declarative base and portable identifier helpers."""

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import DateTime
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.types import TypeDecorator

SCHEMA_REVISION = "0003_deterministic_engine"


class UTCDateTime(TypeDecorator[datetime]):
    """Reject naive input and restore UTC on SQLite, which drops timezone metadata."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamps must be timezone-aware")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class Base(DeclarativeBase):
    """Base for tenant-scoped persistence models."""


def new_id() -> str:
    """Generate a stable string UUID for SQLite and PostgreSQL portability."""

    return str(uuid4())


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(UTC)
