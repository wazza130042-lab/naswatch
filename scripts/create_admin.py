"""
Create (or reset) the first NASWatch administrator.

A fresh install has no accounts, so the operator normally creates the first
administrator through the UI **first-run setup** screen. This script is the
headless equivalent for servers, containers and disaster recovery — the API
never accepts unauthenticated account creation.

Usage:
    python scripts/create_admin.py --email admin@example.com            # prompt for password
    python scripts/create_admin.py --email admin@example.com --password '...'
    python scripts/create_admin.py --email admin@example.com --force    # reset an existing admin
    python scripts/create_admin.py --db-url postgresql://u:p@host/naswatch --email ...

Both NASWATCH_ADMIN_EMAIL and NASWATCH_ADMIN_PASSWORD are honoured as
defaults, and --db-path / --db-url default to NASWATCH_DB_PATH / NASWATCH_DB_URL.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from naswatch.auth.password_policy import WeakPasswordError, validate_password
from naswatch.auth.users import UserStore
from naswatch.storage.factory import get_db_path, get_db_url
from naswatch.storage.models import UserRole


def _prompt_password() -> str:
    """Read and confirm a password interactively."""
    first = getpass.getpass("Administrator password: ")
    second = getpass.getpass("Confirm password: ")
    if first != second:
        raise SystemExit("error: the passwords do not match")
    return first


def _resolve_password(password: str | None, username: str) -> str:
    """Return the password from the CLI, the environment, or an interactive prompt."""
    password = password or os.environ.get("NASWATCH_ADMIN_PASSWORD") or ""
    if not password:
        if not sys.stdin.isatty():
            raise SystemExit(
                "error: no password supplied (use --password or NASWATCH_ADMIN_PASSWORD)"
            )
        password = _prompt_password()
    problems = validate_password(password, username=username)
    if problems:
        raise SystemExit("error: weak password — " + " ".join(problems))
    return password


def main() -> int:
    parser = argparse.ArgumentParser(description="Create or reset a NASWatch administrator account.")
    parser.add_argument(
        "--email",
        default=os.environ.get("NASWATCH_ADMIN_EMAIL", ""),
        help="Administrator email/username (default: NASWATCH_ADMIN_EMAIL)",
    )
    parser.add_argument("--password", default=None, help="Password (default: prompt / NASWATCH_ADMIN_PASSWORD)")
    parser.add_argument("--db-path", default=get_db_path(), help="SQLite database path")
    parser.add_argument("--db-url", default=get_db_url(), help="PostgreSQL URL (overrides --db-path)")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Reset the password and role if the account already exists",
    )
    args = parser.parse_args()

    username = (args.email or "").strip()
    if not username:
        if not sys.stdin.isatty():
            raise SystemExit("error: --email (or NASWATCH_ADMIN_EMAIL) is required")
        username = input("Administrator email: ").strip()
    if "@" not in username or username.startswith("@") or username.endswith("@"):
        raise SystemExit("error: enter a valid email address")

    store = UserStore(db_path=None if args.db_url else args.db_path, db_url=args.db_url)

    existing = store.get_by_username(username)
    if existing is not None:
        if not args.force:
            raise SystemExit(
                f"error: {username} already exists (use --force to reset its password)"
            )
        try:
            store.reset_password(existing.id, _resolve_password(args.password, username))
        except WeakPasswordError as exc:
            raise SystemExit(f"error: weak password — {exc}")
        store.update_user(existing.id, role=UserRole.ADMIN, active=True)
        print(f"Reset the password for existing administrator {username}.")
        return 0

    try:
        store.create_user(username, _resolve_password(args.password, username), UserRole.ADMIN)
    except WeakPasswordError as exc:
        raise SystemExit(f"error: weak password — {exc}")
    print(f"Created administrator {username}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
