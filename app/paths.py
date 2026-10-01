from __future__ import annotations

from pathlib import Path

from .config import Settings


class AppPaths:
    """Resolves the data, asset and backup folders (relative paths are relative to the project root)."""

    def __init__(self, s: Settings):
        root = s.root
        self.data_directory = self._resolve(s.app.data_directory, root, "data")
        self.asset_directory = self._resolve(s.app.asset_directory, root, str(Path("data") / "assets"))
        self.backup_directory = self._resolve(s.app.backup_directory, root, "backups") if s.app.backup_directory.strip() else None
        self.log_directory = self._resolve(s.log_directory, root, "logs")

    @staticmethod
    def _resolve(configured: str, root: Path, fallback: str) -> Path:
        p = Path(configured.strip() or fallback)
        return p if p.is_absolute() else (root / p).resolve()

    @property
    def logo_directory(self) -> Path:
        return self.asset_directory / "logos"

    @property
    def database_file(self) -> Path:
        return self.data_directory / "service-dashboard.db"

    def ensure_created(self) -> None:
        for d in (self.data_directory, self.logo_directory, self.log_directory):
            d.mkdir(parents=True, exist_ok=True)
