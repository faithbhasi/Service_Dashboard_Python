"""The only contract the rest of the application uses to talk to a directory.

Services and routers must never import a directory client library or a concrete provider; an architecture test enforces that.
"""
from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Generic, Protocol, TypeVar

from ...errors import ModuleUnavailableError

T = TypeVar("T")


class ObjectKind(enum.Enum):
    User = "User"
    Computer = "Computer"
    Group = "Group"


class UserFilter(enum.Enum):
    All = "All"
    Locked = "Locked"
    Disabled = "Disabled"
    Enabled = "Enabled"
    AccountExpired = "AccountExpired"


class ComputerFilter(enum.Enum):
    All = "All"
    Enabled = "Enabled"
    Disabled = "Disabled"


# MemberKind uses the same names as ObjectKind
MemberKind = ObjectKind


@dataclass(frozen=True)
class ReadOptions:
    """Attribute names that admins can configure in Settings."""

    employee_id_attribute: str = "employeeID"
    computer_last_user_attribute: str | None = None


@dataclass(frozen=True)
class ObjectRef:
    id: uuid.UUID
    name: str
    kind: ObjectKind


@dataclass
class PagedResult(Generic[T]):
    items: list[T] = field(default_factory=list)
    total: int = 0
    page: int = 1
    page_size: int = 0
    # True when the directory had more matches than the configured search limit, so total is a lower bound.
    total_is_capped: bool = False


@dataclass(frozen=True)
class UserSearch:
    text: str | None
    filter: UserFilter
    page: int
    page_size: int
    ou_dn: str | None
    limit: int
    options: ReadOptions
    department: str | None = None
    title: str | None = None


@dataclass(frozen=True)
class ComputerSearch:
    text: str | None
    filter: ComputerFilter
    page: int
    page_size: int
    ou_dn: str | None
    limit: int
    options: ReadOptions
    os_type: str | None = None


@dataclass(frozen=True)
class GroupSearch:
    text: str | None
    page: int
    page_size: int
    limit: int


@dataclass(frozen=True)
class MemberSearch:
    text: str | None
    kind: MemberKind | None
    page: int
    page_size: int


# The operating-system families offered in the Computers filter, and the text each one matches in operatingSystem.
COMPUTER_OS_TYPES: dict[str, list[str]] = {
    "windows11": ["Windows 11"],
    "windows10": ["Windows 10"],
    "windowsserver": ["Windows Server"],
    "macos": ["macOS", "Mac OS"],
    "linux": ["Linux", "Ubuntu", "Red Hat", "CentOS", "Debian"],
}


def os_type_match(key: str | None) -> list[str] | None:
    """The substrings for a known key, or None when the key is empty or not one of the offered families."""
    return COMPUTER_OS_TYPES.get(key.strip().lower()) if key and key.strip() else None


@dataclass(frozen=True)
class UacFlagInfo:
    name: str
    meaning: str


@dataclass
class DirectoryUser:
    id: uuid.UUID
    dn: str = ""
    ou: str = ""
    sam_account_name: str = ""
    user_principal_name: str | None = None
    display_name: str | None = None
    given_name: str | None = None
    surname: str | None = None
    email: str | None = None
    employee_id: str | None = None
    title: str | None = None
    department: str | None = None
    office: str | None = None
    phone: str | None = None
    mobile: str | None = None
    description: str | None = None
    manager: ObjectRef | None = None
    enabled: bool = True
    locked_out: bool = False
    account_expiry: str = "Never"  # Never, Expires or Expired
    account_expires_utc: datetime | None = None
    password_status: str = "Unknown"  # Expires, Expired, NeverExpires, MustChange or Unknown
    password_expires_utc: datetime | None = None
    password_last_set_utc: datetime | None = None
    last_logon_utc: datetime | None = None  # lastLogonTimestamp: replicates with a delay of up to about 14 days
    created_utc: datetime | None = None
    changed_utc: datetime | None = None
    resultant_pso: str | None = None
    user_account_control: int = 0
    uac_flags: list[UacFlagInfo] = field(default_factory=list)
    primary_group_id: int = 0
    admin_count: bool = False


@dataclass
class DirectoryComputer:
    id: uuid.UUID
    dn: str = ""
    ou: str = ""
    name: str = ""
    dns_host_name: str | None = None
    enabled: bool = True
    operating_system: str | None = None
    os_version: str | None = None
    last_logon_utc: datetime | None = None
    password_last_set_utc: datetime | None = None
    managed_by: ObjectRef | None = None
    description: str | None = None
    changed_utc: datetime | None = None
    created_utc: datetime | None = None
    last_logged_in_user: str | None = None
    admin_count: bool = False


@dataclass
class DirectoryGroup:
    id: uuid.UUID
    dn: str = ""
    ou: str = ""
    name: str = ""
    description: str | None = None
    scope: str = "Global"  # Global, DomainLocal or Universal
    type: str = "Security"  # Security or Distribution
    managed_by: ObjectRef | None = None
    admin_count: bool = False
    member_count: int | None = None
    primary_group_token: int | None = None


@dataclass(frozen=True)
class NestedMembership:
    group: DirectoryGroup
    via: str | None


@dataclass
class Memberships:
    direct: list[DirectoryGroup] = field(default_factory=list)
    nested: list[NestedMembership] = field(default_factory=list)
    primary: DirectoryGroup | None = None


@dataclass
class GroupMember:
    id: uuid.UUID
    kind: MemberKind
    name: str = ""
    sam_account_name: str | None = None
    email: str | None = None
    dn: str = ""
    enabled: bool | None = None


@dataclass(frozen=True)
class DirectoryOu:
    dn: str
    name: str
    has_children: bool


@dataclass(frozen=True)
class DirectoryChange:
    field: str
    from_: str | None
    to: str | None


@dataclass(frozen=True)
class DryRunCheck:
    name: str
    passed: bool
    detail: str | None = None


class DirectoryErrors:
    NOT_FOUND = "NotFound"
    PERMISSION_DENIED = "PermissionDenied"
    PASSWORD_REJECTED = "PasswordRejected"
    ALREADY_MEMBER = "AlreadyMember"
    NOT_MEMBER = "NotMember"
    CONSTRAINT = "ConstraintViolation"
    UNKNOWN = "Unknown"


@dataclass
class DirectoryResult:
    """Outcome of a write or a dry-run. Messages never contain passwords."""

    success: bool
    dry_run: bool
    error_code: str | None = None
    message: str | None = None
    changes: list[DirectoryChange] = field(default_factory=list)
    checks: list[DryRunCheck] = field(default_factory=list)

    @staticmethod
    def ok(dry_run: bool, changes=None, checks=None, message: str | None = None) -> DirectoryResult:
        return DirectoryResult(True, dry_run, None, message, list(changes or []), list(checks or []))

    @staticmethod
    def fail(dry_run: bool, code: str, message: str, checks=None) -> DirectoryResult:
        return DirectoryResult(False, dry_run, code, message, [], list(checks or []))


@dataclass(frozen=True)
class ResetPasswordOptions:
    must_change_at_next_sign_in: bool
    unlock_account: bool


@dataclass(frozen=True)
class ConnectionStep:
    name: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class ConnectionTestResult:
    success: bool
    steps: list[ConnectionStep]


class DirectoryUnavailableError(ModuleUnavailableError):
    """The directory could not be reached. Mapped to a 503 by the global exception handler."""

    def __init__(self, technical: str, inner: Exception | None = None):
        super().__init__("The directory server could not be reached. Try again shortly.", inner)
        self.technical = technical


@dataclass(frozen=True)
class SuggestedAllowlists:
    """Allowlists a provider can suggest for a brand new install. Only the Fake provider does, so local development works out of the box."""

    user_ous: list[str]
    computer_ous: list[str]
    manageable_groups: list[str]
    protected_groups: list[str]


class DirectoryProvider(Protocol):
    provider_name: str
    base_dn: str
    suggested_defaults: SuggestedAllowlists | None

    # ---- reads
    def search_users(self, s: UserSearch) -> PagedResult[DirectoryUser]: ...
    def get_user(self, id: uuid.UUID, options: ReadOptions) -> DirectoryUser | None: ...
    def search_computers(self, s: ComputerSearch) -> PagedResult[DirectoryComputer]: ...
    def get_computer(self, id: uuid.UUID, options: ReadOptions) -> DirectoryComputer | None: ...
    def search_groups(self, s: GroupSearch) -> PagedResult[DirectoryGroup]: ...
    def get_group(self, id: uuid.UUID) -> DirectoryGroup | None: ...
    def get_group_by_dn(self, dn: str) -> DirectoryGroup | None: ...
    def get_memberships(self, object_id: uuid.UUID, kind: ObjectKind) -> Memberships | None: ...
    def search_group_members(self, group_id: uuid.UUID, s: MemberSearch) -> PagedResult[GroupMember]: ...
    def browse_ous(self, parent_dn: str | None) -> list[DirectoryOu]: ...
    def search_ous(self, text: str, limit: int) -> list[DirectoryOu]: ...
    def get_ou(self, dn: str) -> DirectoryOu | None: ...
    def lockout_times(self, since_utc: datetime, max_items: int) -> list[datetime]: ...
    def count_users(self, flt: UserFilter) -> int: ...
    def count_computers(self, flt: ComputerFilter) -> int: ...

    # ---- writes: every one supports a dry run that changes nothing
    def reset_password(self, user_id: uuid.UUID, new_password: str, options: ResetPasswordOptions, dry_run: bool) -> DirectoryResult: ...
    def unlock(self, user_id: uuid.UUID, dry_run: bool) -> DirectoryResult: ...
    def set_enabled(self, object_id: uuid.UUID, kind: ObjectKind, enabled: bool, dry_run: bool) -> DirectoryResult: ...
    def move(self, object_id: uuid.UUID, kind: ObjectKind, target_ou_dn: str, dry_run: bool) -> DirectoryResult: ...
    def add_to_groups(self, member_id: uuid.UUID, group_ids: list[uuid.UUID], dry_run: bool) -> DirectoryResult: ...
    def remove_from_groups(self, member_id: uuid.UUID, group_ids: list[uuid.UUID], dry_run: bool) -> DirectoryResult: ...

    def test_connection(self) -> ConnectionTestResult: ...
