"""Administrative command line interface: ``python -m app.cli``.

Subcommands cover the operations that must never be reachable over HTTP:
schema migration, one-shot admin bootstrap, admin password changes and license
key generation. ``keygen`` prints each plaintext key exactly once; only its
HMAC is persisted, so a lost key cannot be recovered and must be reissued.
"""

import argparse
import getpass
import sys
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path

from alembic.config import Config
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from alembic import command
from app.config import Settings, get_settings
from app.keys import generate_license_key, hash_license_key, mask_license_key
from app.logging_config import configure_logging, get_logger
from app.security.passwords import hash_password

logger = get_logger("cli")
SERVER_ROOT = Path(__file__).resolve().parent.parent
KEYGEN_COLLISION_RETRIES = 5
EXIT_CONFIG_ERROR = 2
EXIT_FAILURE = 1


def load_settings() -> Settings:
    """Load settings, or exit with an actionable message if the env is incomplete."""
    try:
        settings = get_settings()
    except ValidationError as exc:
        names = sorted({str(err["loc"][0]) for err in exc.errors()})
        detail = "invalid or missing environment variable(s): " + ", ".join(names)
        sys.stderr.write(
            f"configuration error: {detail}\n"
            "copy server/.env.example to server/.env and fill in the secrets "
            "(LICENSE_JWT_SECRET needs 32+ characters, peppers 16+)\n"
        )
        raise SystemExit(EXIT_CONFIG_ERROR) from None
    settings.validate_runtime()
    return settings


@lru_cache(maxsize=1)
def session_factory() -> Callable[[], Session]:
    """Import the DB layer lazily.

    ``app.db`` builds its engine at import time, which needs a complete
    environment. Deferring the import keeps a missing-secret misconfiguration
    a clean ``exit(2)`` instead of an import-time traceback.
    """
    from app.db import SessionLocal

    return SessionLocal


def alembic_config(settings: Settings) -> Config:
    """Build an Alembic config rooted at the server package, cwd-independent."""
    config = Config(str(SERVER_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(SERVER_ROOT / "alembic"))
    config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)
    return config


def read_password(use_stdin: bool, *, confirm: bool) -> str:
    """Read a password from stdin or an interactive prompt, confirmed once."""
    try:
        if use_stdin:
            if sys.stdin.isatty():
                sys.stderr.write("warning: reading a password from an interactive terminal\n")
            line = sys.stdin.readline()
            if not line:
                sys.stderr.write("error: no password received on stdin\n")
                raise SystemExit(EXIT_FAILURE)
            return line.rstrip("\r\n")
        password = getpass.getpass("Password: ")
        if confirm and password != getpass.getpass("Confirm password: "):
            sys.stderr.write("error: passwords do not match\n")
            raise SystemExit(EXIT_FAILURE)
        return password
    except (EOFError, OSError):
        sys.stderr.write("error: could not read a password (no interactive terminal?)\n")
        raise SystemExit(EXIT_FAILURE) from None


def cmd_migrate(args: argparse.Namespace, settings: Settings) -> int:
    """Run ``alembic upgrade head``."""
    revision = args.revision or "head"
    command.upgrade(alembic_config(settings), revision)
    sys.stdout.write(f"database upgraded to {revision}\n")
    return 0


def cmd_init_db(args: argparse.Namespace, settings: Settings) -> int:
    """Migrate, then bootstrap the first admin from ADMIN_USERNAME/ADMIN_PASSWORD."""
    command.upgrade(alembic_config(settings), "head")
    logger.info("database schema applied")

    if args.no_bootstrap:
        return 0

    username = settings.ADMIN_USERNAME
    password = settings.ADMIN_PASSWORD.get_secret_value() if settings.ADMIN_PASSWORD else None
    if not username or not password:
        logger.info("no admin bootstrap requested: set ADMIN_USERNAME and ADMIN_PASSWORD")
        return 0

    from app.models import Admin

    with session_factory()() as session:
        existing = session.scalar(select(func.count()).select_from(Admin))
        if existing:
            logger.info("admin table is not empty, skipping bootstrap")
            return 0
        try:
            password_hash = hash_password(password, settings)
        except ValueError as exc:
            sys.stderr.write(f"error: ADMIN_PASSWORD rejected: {exc}\n")
            return EXIT_FAILURE
        session.add(
            Admin(
                username=username,
                password_hash=password_hash,
                is_active=True,
                is_superuser=True,
            )
        )
        session.commit()
    logger.info("bootstrapped superuser from environment", extra={"app_username": username})
    return 0


def cmd_admin_create(args: argparse.Namespace, settings: Settings) -> int:
    """Create an administrator account with an argon2id password hash."""
    username = args.username.strip()
    if not username:
        sys.stderr.write("error: --username must not be empty\n")
        return EXIT_FAILURE

    password = read_password(args.password_stdin, confirm=not args.password_stdin)
    try:
        password_hash = hash_password(password, settings)
    except ValueError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return EXIT_FAILURE

    from app.models import Admin

    with session_factory()() as session:
        if session.scalar(select(Admin).where(Admin.username == username)):
            sys.stderr.write(f"error: admin {username!r} already exists\n")
            return EXIT_FAILURE
        session.add(Admin(username=username, password_hash=password_hash, is_active=True))
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            sys.stderr.write(f"error: admin {username!r} already exists\n")
            return EXIT_FAILURE

    sys.stdout.write(f"created admin {username!r}\n")
    logger.info("admin created", extra={"app_username": username})
    return 0


def cmd_admin_password(args: argparse.Namespace, settings: Settings) -> int:
    """Replace an administrator's password."""
    username = args.username.strip()
    password = read_password(False, confirm=True)
    try:
        password_hash = hash_password(password, settings)
    except ValueError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return EXIT_FAILURE

    from app.models import Admin

    with session_factory()() as session:
        admin = session.scalar(select(Admin).where(Admin.username == username))
        if admin is None:
            sys.stderr.write(f"error: admin {username!r} not found\n")
            return EXIT_FAILURE
        admin.password_hash = password_hash
        session.commit()

    sys.stdout.write(f"password updated for {username!r}\n")
    logger.info("admin password changed", extra={"app_username": username})
    return 0


def cmd_keygen(args: argparse.Namespace, settings: Settings) -> int:
    """Generate license keys, persist only their HMAC, and print them once."""
    if args.count < 1:
        sys.stderr.write("error: --count must be at least 1\n")
        return EXIT_FAILURE

    pepper = settings.license_key_pepper
    generated: list[str] = []

    from app.models import License

    with session_factory()() as session:
        for _ in range(args.count):
            for _attempt in range(KEYGEN_COLLISION_RETRIES):
                plaintext = generate_license_key()
                session.add(License(key_hash=hash_license_key(pepper, plaintext)))
                try:
                    session.commit()
                except IntegrityError:
                    session.rollback()
                    continue
                generated.append(plaintext)
                break
            else:
                session.rollback()
                sys.stderr.write("error: could not generate a unique license key\n")
                return EXIT_FAILURE

    for plaintext in generated:
        sys.stdout.write(plaintext + "\n")
    sys.stdout.flush()
    logger.info(
        "license keys generated",
        extra={"app_count": len(generated), "app_masked": [mask_license_key(k) for k in generated]},
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Assemble the argument parser."""
    parser = argparse.ArgumentParser(
        prog="python -m app.cli", description="License server administration."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    migrate = subparsers.add_parser("migrate", help="apply database migrations")
    migrate.add_argument("--revision", default="head", help="target revision (default: head)")
    migrate.set_defaults(handler=cmd_migrate)

    init_db = subparsers.add_parser(
        "init-db", help="apply migrations and optionally bootstrap the first admin"
    )
    init_db.add_argument(
        "--no-bootstrap",
        action="store_true",
        help="migrate only, ignoring ADMIN_USERNAME/ADMIN_PASSWORD",
    )
    init_db.set_defaults(handler=cmd_init_db)

    admin_create = subparsers.add_parser("admin-create", help="create an administrator")
    admin_create.add_argument("--username", required=True, help="administrator username")
    admin_create.add_argument(
        "--password-stdin",
        action="store_true",
        help="read the password from the first line of stdin instead of prompting",
    )
    admin_create.set_defaults(handler=cmd_admin_create)

    admin_password = subparsers.add_parser(
        "admin-password", help="set a new password for an administrator"
    )
    admin_password.add_argument("username", help="administrator username")
    admin_password.set_defaults(handler=cmd_admin_password)

    keygen = subparsers.add_parser(
        "keygen",
        help="generate license keys and print them once (only the HMAC is stored)",
    )
    keygen.add_argument("--count", type=int, default=1, help="number of keys (default: 1)")
    keygen.set_defaults(handler=cmd_keygen)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``python -m app.cli``."""
    args = build_parser().parse_args(argv)
    settings = load_settings()
    configure_logging(settings, stream=sys.stderr)
    handler: Callable[[argparse.Namespace, Settings], int] = args.handler
    return handler(args, settings)


if __name__ == "__main__":
    raise SystemExit(main())
