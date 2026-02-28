from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from db.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    # Only the argon2 hash is ever stored — plaintext never touches the DB
    hashed_password: Mapped[str] = mapped_column(String, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)

    # Store SHA-256 hash of the token, not the raw value.
    # If DB is leaked, attacker cannot use these directly (must brute-force preimage).
    token_hash: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)

    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Revoked flag rather than delete: lets us detect reuse of rotated tokens
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)

    # Track which token this one replaced — enables full family revocation on reuse
    replaced_by_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("refresh_tokens.id"), nullable=True
    )

    user: Mapped["User"] = relationship(back_populates="refresh_tokens")
