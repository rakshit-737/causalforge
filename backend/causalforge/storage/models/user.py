"""Tenant-scoped analyst identity model."""

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from causalforge.storage.models.base import Base, UTCDateTime, new_id, utc_now

if TYPE_CHECKING:
    from causalforge.storage.models.tenant import Tenant


class User(Base):
    """Minimal identity record used to prove tenant-scoped repository access."""

    __tablename__ = "users"
    __table_args__ = (Index("ix_users_tenant_subject", "tenant_id", "subject", unique=True),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(80), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), default=utc_now, nullable=False
    )

    tenant: Mapped["Tenant"] = relationship(back_populates="users")
