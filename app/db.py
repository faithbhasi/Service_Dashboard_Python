"""SQLite via SQLAlchemy: WAL mode, UTC datetimes, a small migration runner, append-only audit triggers."""
from __future__ import annotations

import enum
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import (
    BigInteger, Boolean, DateTime, Enum, ForeignKey, Index, Integer, String, Text, TypeDecorator, create_engine, event, text,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from .util import new_id, utcnow


class UtcDateTime(TypeDecorator):
    """SQLite has no time zone: always store UTC and always hand back timezone-aware UTC."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is not None:
            value = value.astimezone(UTC).replace(tzinfo=None)
        return value

    def process_result_value(self, value, dialect):
        return None if value is None else value.replace(tzinfo=UTC)


class Base(DeclarativeBase):
    pass


class AuditCategory(enum.IntEnum):
    Logon = 1
    Access = 2
    Admin = 3


class AuditResult:
    SUCCESS = "Success"
    FAILURE = "Failure"
    DENIED = "Denied"
    VALIDATED = "Validated (no change made)"


class AppUser(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    # Okta "sub" claim (or "dev|name" for development sign-in).
    subject: Mapped[str] = mapped_column(String(256), unique=True)
    email: Mapped[str] = mapped_column(String(320), default="", index=True)
    display_name: Mapped[str] = mapped_column(String(256), default="")
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_utc: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    last_sign_in_utc: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    # Okta groups seen at the last sign-in (JSON array); kept out of the session to keep it small.
    okta_groups_json: Mapped[str] = mapped_column(Text, default="[]")
    theme_preference: Mapped[str] = mapped_column(String(10), default="system")
    nav_collapsed: Mapped[bool] = mapped_column(Boolean, default=False)
    user_roles: Mapped[list[UserRole]] = relationship(back_populates="user", cascade="all, delete-orphan")


class Role(Base):
    __tablename__ = "roles"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_system: Mapped[bool] = mapped_column(Boolean, default=False)
    created_utc: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    # What this role may manage in Active Directory (JSON, see models.AdScope); null = no extra limit.
    ad_scope_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    permissions: Mapped[list[RolePermission]] = relationship(cascade="all, delete-orphan", lazy="selectin")


class RolePermission(Base):
    __tablename__ = "role_permissions"
    role_id: Mapped[str] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)
    permission: Mapped[str] = mapped_column(String(100), primary_key=True)


class UserRole(Base):
    __tablename__ = "user_roles"
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    role_id: Mapped[str] = mapped_column(ForeignKey("roles.id", ondelete="RESTRICT"), primary_key=True)
    user: Mapped[AppUser] = relationship(back_populates="user_roles")
    role: Mapped[Role] = relationship()


class GroupMapping(Base):
    __tablename__ = "group_mappings"
    __table_args__ = (Index("ix_group_mappings_group_role", "okta_group", "role_id", unique=True),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    okta_group: Mapped[str] = mapped_column(String(256))
    role_id: Mapped[str] = mapped_column(ForeignKey("roles.id", ondelete="RESTRICT"))
    role: Mapped[Role] = relationship()


class SettingEntry(Base):
    """Runtime settings edited in the UI: one JSON document per key."""

    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    json: Mapped[str] = mapped_column(Text, default="{}")
    updated_utc: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(256), nullable=True)


class LogoAsset(Base):
    __tablename__ = "logo_assets"
    kind: Mapped[str] = mapped_column(String(30), primary_key=True)  # logoLight, logoDark or favicon
    file_name: Mapped[str] = mapped_column(String(100), default="")
    content_type: Mapped[str] = mapped_column(String(50), default="")
    size_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    updated_utc: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class AuditLog(Base):
    """Append-only: the application never updates rows and only deletes them through the retention job."""

    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_category_time", "category", "time_utc"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    time_utc: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, index=True)
    category: Mapped[AuditCategory] = mapped_column(Enum(AuditCategory, native_enum=False, values_callable=lambda e: [m.name for m in e]))
    user_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    user_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    action: Mapped[str] = mapped_column(String(200), index=True)
    module: Mapped[str | None] = mapped_column(String(50), nullable=True)
    target: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Stable identifier of the target (for AD objects the objectGUID).
    target_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    previous_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    new_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    result: Mapped[str] = mapped_column(String(50), default=AuditResult.SUCCESS)
    error: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    justification: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    ticket_number: Mapped[str | None] = mapped_column(String(100), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)


class UserSession(Base):
    """Server-side session: the browser only holds an opaque random id, never claims or tokens."""

    __tablename__ = "user_sessions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    data: Mapped[str] = mapped_column(Text, default="{}")
    created_utc: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, index=True)
    updated_utc: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class SchemaMigration(Base):
    __tablename__ = "schema_migrations"
    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    applied_utc: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


# ---------------------------------------------------------------------------------------------- engine and migrations

PRAGMAS = "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;"


def create_db_engine(db_file: Path | str) -> Engine:
    url = "sqlite://" if str(db_file) == ":memory:" else f"sqlite:///{db_file}"
    engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 30}, future=True)

    @event.listens_for(engine, "connect")
    def _pragmas(dbapi_conn, _):  # WAL mode and a busy timeout on every SQLite connection
        cur = dbapi_conn.cursor()
        for stmt in PRAGMAS.split(";"):
            if stmt.strip():
                cur.execute(stmt)
        cur.close()

    return engine


def make_session_factory(engine: Engine) -> sessionmaker:
    return sessionmaker(engine, expire_on_commit=False, autoflush=True)


def _m001_initial(conn) -> None:
    Base.metadata.create_all(conn, checkfirst=True)
    # The audit table is append-only: rows can never be edited. (Old rows are removed by the retention job only.)
    conn.execute(text("CREATE TRIGGER IF NOT EXISTS audit_logs_no_update BEFORE UPDATE ON audit_logs "
                      "BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END;"))


# Add new schema changes at the end as ("id", function(conn)). Never edit an applied migration.
MIGRATIONS = [("001_initial", _m001_initial)]


def migrate(engine: Engine) -> list[str]:
    """Applies pending migrations in order and returns the ids that were applied."""
    applied: list[str] = []
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE IF NOT EXISTS schema_migrations (id VARCHAR(100) PRIMARY KEY, applied_utc DATETIME)"))
        done = {r[0] for r in conn.execute(text("SELECT id FROM schema_migrations"))}
        for mid, fn in MIGRATIONS:
            if mid in done:
                continue
            fn(conn)
            conn.execute(text("INSERT INTO schema_migrations (id, applied_utc) VALUES (:i, :t)"),
                         {"i": mid, "t": utcnow().astimezone(UTC).replace(tzinfo=None)})
            applied.append(mid)
    return applied
