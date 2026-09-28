"""Explicitly tenant-scoped user repository."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from causalforge.storage.models import User


class UserRepository:
    """Repository methods require a tenant scope for every read and write."""

    def create(self, session: Session, *, tenant_id: str, subject: str, role: str) -> User:
        user = User(tenant_id=tenant_id, subject=subject, role=role)
        session.add(user)
        session.flush()
        return user

    def list_for_tenant(self, session: Session, *, tenant_id: str) -> list[User]:
        statement = select(User).where(User.tenant_id == tenant_id).order_by(User.subject)
        return list(session.scalars(statement))
