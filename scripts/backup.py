#!/usr/bin/env python3
"""
NASWatch backup/restore.

Supports both storage engines selected at runtime:
  - SQLite (NASWATCH_DB_PATH, default data/inventory.db): online hot-backup via
    the sqlite3 backup API (safe under WAL), with optional gzip.
  - PostgreSQL (NASWATCH_DB_URL): pg_dump compatibility backup.

Examples:
    # Back up to ./backups/ with a timestamped file (and gzip for PG/SQLite)
    python3 scripts/backup.py
    python3 scripts/backup.py --target/backup >/backups --compress gzip

    # Restore
    python3 scripts/backup.py --restore backups/backup-20260905.sql.gz

Recommended production scheduling (systemd timer / cron):
    0 2 * * * cd /opt/naswatch && ./venv/bin/python scripts/backup.py --target /backups --compress gzip
"""

from __future__ import annotations

import argparse
import gzip
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from naswatch.storage.factory import get_db_path, get_db_url  # noqa: E402


def _is_postgres(db_url: str | None) -> bool:
    return bool(db_url) and (db_url.startswith("postgres://") or db_url.startswith("postgresql://"))


def _timestamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%d-%H%M%S")


def _write_file(path: Path, data: bytes, compress: str | None) -> Path:
    if compress == "gzip":
        out = path.with_suffix(path.suffix + ".gz")
        with gzip.open(out, "wb") as f:
            f.write(data)
        return out
    path.write_bytes(data)
    return path


def backup_sqlite(db_path: str, out_dir: Path, compress: str | None) -> Path:
    import sqlite3

    src = sqlite3.connect(db_path)
    staging = out_dir / f"inventory-{_timestamp()}.db"
    dst = sqlite3.connect(staging)
    try:
        src.backup(dst)  # online, consistent snapshot even under WAL
    finally:
        dst.close()
        src.close()

    check = sqlite3.connect(staging)
    (ok,) = check.execute("PRAGMA integrity_check").fetchone()
    check.close()
    if ok != "ok":
        raise RuntimeError(f"SQLite integrity check failed: {ok}")

    data = staging.read_bytes()
    if compress == "gzip":
        out = _write_file(staging, data, compress)
        staging.unlink()
        return out
    return staging


def backup_postgres(db_url: str, out_dir: Path, compress: str | None) -> Path:
    if shutil.which("pg_dump") is None:
        raise RuntimeError("pg_dump is required for PostgreSQL backups (install postgresql-client).")
    env = dict(os.environ)
    env["PGPASSWORD"] = db_url.split("@")[0].rsplit(":", 1)[-1] or ""
    proc = subprocess.run(
        ["pg_dump", "--clean", "--if-exists", "--no-owner", "--no-privileges", db_url],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"pg_dump failed: {proc.stderr.decode()[:500]}")
    return _write_file(out_dir / f"naswatch-pg-{_timestamp()}.sql", proc.stdout, compress)


def restore_sqlite(backup_path: Path, db_path: str, compress: str | None) -> None:
    import sqlite3

    raw = gzip.open(backup_path, "rb").read() if compress == "gzip" else backup_path.read_bytes()
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        tf.write(raw)
        tmp = tf.name
    try:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        shutil.move(tmp, db_path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    check = sqlite3.connect(db_path)
    (ok,) = check.execute("PRAGMA integrity_check").fetchone()
    check.close()
    if ok != "ok":
        raise RuntimeError(f"Restored SQLite failed integrity check: {ok}")


def restore_postgres(backup_path: Path, db_url: str, compress: str | None) -> None:
    if shutil.which("psql") is None:
        raise RuntimeError("psql is required for PostgreSQL restores.")
    raw = gzip.open(backup_path, "rb").read() if compress == "gzip" else backup_path.read_bytes()
    with tempfile.NamedTemporaryFile(suffix=".sql", delete=False) as tf:
        tf.write(raw)
        tmp = tf.name
    try:
        env = dict(os.environ)
        env["PGPASSWORD"] = db_url.split("@")[0].rsplit(":", 1)[-1] or ""
        proc = subprocess.run(
            ["psql", db_url, "-f", tmp, "-v", "ON_ERROR_STOP=1"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"psql restore failed: {proc.stderr.decode()[:500]}")
    finally:
        os.unlink(tmp)


def main() -> int:
    parser = argparse.ArgumentParser(description="NASWatch backup / restore")
    parser.add_argument("--target", default="backups", help="Output directory (default: backups/)")
    parser.add_argument("--restore", metavar="FILE", help="Restore from a backup file instead of backing up")
    parser.add_argument("--compress", choices=["gzip", "none"], default="gzip",
                        help="Compression for the archive (default: gzip)")
    args = parser.parse_args()

    db_url = get_db_url()
    db_path = get_db_path()
    pg = _is_postgres(db_url)
    compress = None if args.compress == "none" else args.compress

    if args.restore:
        backup_path = Path(args.restore)
        if not backup_path.exists():
            print(f"Backup file not found: {backup_path}")
            return 2
        engine = "postgres" if backup_path.name.startswith("naswatch-pg") else "sqlite"
        if pg and engine != "postgres":
            print("Storage is PostgreSQL but the backup file is a SQLite archive. Aborting.")
            return 2
        if engine == "postgres":
            restore_postgres(backup_path, db_url, compress)
            print(f"Restored PostgreSQL database from {backup_path}")
        else:
            restore_sqlite(backup_path, db_path, compress)
            print(f"Restored SQLite database to {db_path} from {backup_path}")
        return 0

    out_dir = Path(args.target)
    out_dir.mkdir(parents=True, exist_ok=True)
    if pg:
        out = backup_postgres(db_url, out_dir, compress)
    else:
        if not Path(db_path).exists():
            print(f"SQLite database not found at {db_path} (nothing to back up).")
            return 2
        out = backup_sqlite(db_path, out_dir, compress)
    print(f"Backup written: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
