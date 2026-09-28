"""Local development principal adapter.

This is intentionally not presented as production authentication. Until an identity provider is
integrated, the API requires a tenant UUID and a user subject in headers and verifies the pair
against the local tenant/user tables. The self-asserted tenant header alone is never trusted.
"""

from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

from fastapi import Header, HTTPException, Request, status
from sqlalchemy import select

from causalforge.storage.db import Database
from causalforge.storage.models import User


@dataclass(frozen=True)
class Principal:
    """Authenticated local principal and immutable tenant scope."""

    tenant_id: UUID
    user_id: UUID
    subject: str
    role: str

    @property
    def audit_actor(self) -> dict[str, str]:
        """Return the minimal non-secret actor identity for audit records."""

        return {"kind": "user", "id": self.subject, "role": self.role}


def get_principal(
    request: Request,
    tenant_header: Annotated[str | None, Header(alias="X-Tenant-ID")] = None,
    user_header: Annotated[str | None, Header(alias="X-User-ID")] = None,
) -> Principal:
    """Verify the local tenant/user pair before any tenant-scoped API operation."""

    if not tenant_header or not user_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-Tenant-ID and X-User-ID are required",
        )
    try:
        tenant_id = UUID(tenant_header)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid local principal",
        ) from exc

    database: Database = request.app.state.database
    with database.session() as session:
        user = session.scalar(
            select(User).where(
                User.tenant_id == str(tenant_id),
                User.subject == user_header,
            )
        )
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid local principal",
        )
    return Principal(
        tenant_id=tenant_id,
        user_id=UUID(user.id),
        subject=user.subject,
        role=user.role,
    )
