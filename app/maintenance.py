"""Audit retention and the optional online SQLite backup, plus the daily timer that runs them."""
from __future__ import annotations

import asyncio
import shutil
from datetime import timedelta
from pathlib import Path

from sqlalchemy import delete, text
from sqlalchemy.orm import sessionmaker

from .audit import AuditEntry, AuditService
from .config import AppOptions
from .db import AuditLog, AuditResult
from .logging_setup import get_logger
from .paths import AppPaths
from .util import utcnow

log = get_logger("maintenance")


class MaintenanceTasks:
    """Plain methods so they can be called from tests."""

    def __init__(self, factory: sessionmaker, paths: AppPaths, options: AppOptions, audit: AuditService):
        self.factory = factory
        self.paths = paths
        self.options = options
        self.audit = audit

    def purge_audit(self) -> int:
        """Removes audit rows older than the retention period. The removal is itself logged. Returns the number removed."""
        days = self.options.audit_retention_days
        if days <= 0:
            return 0  # 0 = keep forever
        cutoff = utcnow() - timedelta(days=days)
        with self.factory() as db:
            removed = db.execute(delete(AuditLog).where(AuditLog.time_utc < cutoff)).rowcount or 0
            db.commit()
        if removed > 0:
            log.info("Audit retention removed %s records older than %s", removed, cutoff.strftime("%Y-%m-%d %H:%M:%SZ"))
            self.audit.write(AuditEntry(action="maintenance.auditRetention", module="core", target="Audit log",
                                        new_value=f"Removed {removed} records older than {cutoff:%Y-%m-%d %H:%M:%SZ} (retention {days} days)"))
        return removed

    def backup(self) -> str | None:
        """Consistent online backup: VACUUM INTO writes a complete copy of the database (safe while WAL mode is on), and the
        logo folder is copied beside it. Keeps the newest BackupRetentionCount backups."""
        root = self.paths.backup_directory
        if root is None:
            return None
        folder = root / ("backup-" + utcnow().strftime("%Y%m%d-%H%M%S-%f")[:-3])
        folder.mkdir(parents=True, exist_ok=True)
        target = folder / self.paths.database_file.name
        try:
            with self.factory() as db:
                escaped = str(target).replace("'", "''")
                db.execute(text(f"VACUUM INTO '{escaped}'"))
            if self.paths.asset_directory.exists():
                shutil.copytree(self.paths.asset_directory, folder / "assets", dirs_exist_ok=True)
            self._prune(root, max(1, self.options.backup_retention_count))
            log.info("Database backup written to %s", folder)
            self.audit.write(AuditEntry(action="maintenance.backup", module="core", target="SQLite database and assets", new_value=str(folder)))
            return str(folder)
        except Exception:
            log.exception("Database backup failed")
            self.audit.write(AuditEntry(action="maintenance.backup", module="core", target="SQLite database and assets",
                                        result=AuditResult.FAILURE, error="Backup failed; see the application log"))
            return None

    @staticmethod
    def _prune(root: Path, keep: int) -> None:
        old = sorted((d for d in root.glob("backup-*") if d.is_dir()), key=lambda d: d.name, reverse=True)[keep:]
        for d in old:
            shutil.rmtree(d, ignore_errors=True)


async def maintenance_loop(tasks: MaintenanceTasks, options: AppOptions, first_delay_seconds: float = 30) -> None:
    """A simple daily timer: retention on start and then once a day, plus the optional daily backup. Not a job framework."""
    try:
        await asyncio.sleep(first_delay_seconds)
        while True:
            try:
                await asyncio.to_thread(tasks.purge_audit)
                if options.daily_backup_enabled:
                    await asyncio.to_thread(tasks.backup)
            except Exception:
                log.exception("Daily maintenance failed")
            await asyncio.sleep(24 * 3600)
    except asyncio.CancelledError:
        return
