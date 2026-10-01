"""Turns raw AD attribute values into the account and password status shown in the UI.

Shared by every provider so the Fake provider behaves exactly like real AD.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from .provider import UacFlagInfo

ACCOUNT_DISABLE = 0x2
LOCKOUT = 0x10
PASSWD_NOTREQD = 0x20
PASSWD_CANT_CHANGE = 0x40
ENCRYPTED_TEXT_PWD_ALLOWED = 0x80
NORMAL_ACCOUNT = 0x200
DONT_EXPIRE_PASSWORD = 0x10000
SMARTCARD_REQUIRED = 0x40000
TRUSTED_FOR_DELEGATION = 0x80000
NOT_DELEGATED = 0x100000
USE_DES_KEY_ONLY = 0x200000
DONT_REQUIRE_PREAUTH = 0x400000
PASSWORD_EXPIRED = 0x800000
TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000

# Bits of msDS-User-Account-Control-Computed that reflect the live state.
COMPUTED_LOCKOUT = 0x10
COMPUTED_PASSWORD_EXPIRED = 0x800000

NEVER_FILETIME = (1 << 63) - 1  # long.MaxValue

_FLAGS = [
    (ACCOUNT_DISABLE, "ACCOUNTDISABLE", "The account is disabled."),
    (LOCKOUT, "LOCKOUT", "The account is locked out."),
    (PASSWD_NOTREQD, "PASSWD_NOTREQD", "No password is required for this account."),
    (PASSWD_CANT_CHANGE, "PASSWD_CANT_CHANGE", "The user cannot change their own password."),
    (ENCRYPTED_TEXT_PWD_ALLOWED, "ENCRYPTED_TEXT_PWD_ALLOWED", "The password may be stored with reversible encryption."),
    (NORMAL_ACCOUNT, "NORMAL_ACCOUNT", "A normal user account."),
    (DONT_EXPIRE_PASSWORD, "DONT_EXPIRE_PASSWORD", "The password never expires."),
    (SMARTCARD_REQUIRED, "SMARTCARD_REQUIRED", "A smart card is required to sign in."),
    (TRUSTED_FOR_DELEGATION, "TRUSTED_FOR_DELEGATION", "Trusted for Kerberos delegation."),
    (NOT_DELEGATED, "NOT_DELEGATED", "The account cannot be delegated."),
    (USE_DES_KEY_ONLY, "USE_DES_KEY_ONLY", "Only DES encryption types are used for this account."),
    (DONT_REQUIRE_PREAUTH, "DONT_REQ_PREAUTH", "Kerberos pre-authentication is not required."),
    (PASSWORD_EXPIRED, "PASSWORD_EXPIRED", "The password has expired."),
    (TRUSTED_TO_AUTH_FOR_DELEGATION, "TRUSTED_TO_AUTH_FOR_DELEGATION", "Trusted to authenticate for delegation."),
]

_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def describe_flags(uac: int) -> list[UacFlagInfo]:
    return [UacFlagInfo(name, meaning) for bit, name, meaning in _FLAGS if uac & bit]


def is_enabled(uac: int) -> bool:
    return (uac & ACCOUNT_DISABLE) == 0


def is_locked_out(computed_uac: int) -> bool:
    """Locked only if the live computed bit says so. An old lockoutTime alone does not mean the account is still locked,
    because the lockout duration may have passed."""
    return (computed_uac & COMPUTED_LOCKOUT) != 0


def from_filetime(ft: int) -> datetime | None:
    if ft <= 0 or ft >= NEVER_FILETIME:
        return None
    try:
        return _EPOCH + timedelta(microseconds=ft // 10)
    except OverflowError:
        return None


def to_filetime(utc: datetime) -> int:
    return int((utc.astimezone(UTC) - _EPOCH) / timedelta(microseconds=1)) * 10


def account_expiry(account_expires_filetime: int, now_utc: datetime) -> tuple[str, datetime | None]:
    if account_expires_filetime in (0, NEVER_FILETIME):
        return "Never", None
    date = from_filetime(account_expires_filetime)
    if date is None:
        return "Never", None
    return ("Expired" if date <= now_utc else "Expires"), date


def password(uac: int, computed_uac: int, pwd_last_set: int, pwd_expiry_computed: int | None, now_utc: datetime) -> tuple[str, datetime | None]:
    """pwd_expiry_computed: msDS-UserPasswordExpiryTimeComputed (already reflects fine-grained policies), 0 or None if unknown."""
    if uac & DONT_EXPIRE_PASSWORD:
        return "NeverExpires", None
    if pwd_last_set == 0:
        return "MustChange", None
    if (computed_uac & COMPUTED_PASSWORD_EXPIRED) or (uac & PASSWORD_EXPIRED):
        return "Expired", from_filetime(pwd_expiry_computed or 0)
    if not pwd_expiry_computed:
        return "Unknown", None
    if pwd_expiry_computed == NEVER_FILETIME:
        return "NeverExpires", None
    date = from_filetime(pwd_expiry_computed)
    if date is None:
        return "Unknown", None
    return ("Expired" if date <= now_utc else "Expires"), date
