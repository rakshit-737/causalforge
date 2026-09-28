"""SQLAlchemy engine/session boundary.

The application may auto-create the small local schema in SQLite. Production deployments must use
Alembic migrations and set ``CF_AUTO_CREATE_SCHEMA=false``.
"""

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from causalforge.storage.models import Base
from causalforge.storage.models.base import SCHEMA_REVISION


class Database:
    """Own an engine and explicit session factory without hiding transaction boundaries."""

    def __init__(self, url: str, *, echo: bool = False) -> None:
        self.url = url
        self.engine: Engine = create_engine(url, echo=echo, future=True)
        self.session_factory = sessionmaker(bind=self.engine, expire_on_commit=False)

    def create_schema(self) -> None:
        """Create local tables for development and tests; use Alembic in production."""

        Base.metadata.create_all(self.engine)

    def check(self, *, require_schema: bool = False) -> None:
        """Check connectivity and, when requested, the current Alembic revision."""

        with self.engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            if require_schema:
                revision = connection.execute(
                    text("SELECT version_num FROM alembic_version")
                ).scalar()
                if revision != SCHEMA_REVISION:
                    raise RuntimeError("database schema revision is not current")

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Yield one caller-owned session and roll back uncommitted failures."""

        session = self.session_factory()
        try:
            yield session
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def dispose(self) -> None:
        """Release pooled connections during application shutdown."""

        self.engine.dispose()
