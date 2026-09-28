"""Tenant persistence model."""

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from causalforge.storage.models.base import Base, UTCDateTime, new_id, utc_now

if TYPE_CHECKING:
    from causalforge.storage.models.user import User


class Tenant(Base):
    """Isolation root for cases, evidence, users, and future graph data."""

    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), default=utc_now, nullable=False
    )

    users: Mapped[list["User"]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan"
    )
