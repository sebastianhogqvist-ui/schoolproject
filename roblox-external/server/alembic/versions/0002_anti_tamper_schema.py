"""anti-tampering: security events table and license restriction tracking

Creates the ``security_events`` table and adds ``restricted_until`` to
``licenses`` for temporary restriction duration management.  Reversible.

Revision ID: 0002_anti_tamper_schema
Revises: 0001_initial_schema
Create Date: 2026-10-09
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0002_anti_tamper_schema"
down_revision: str | None = "0001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add the security_events table and the restricted_until column."""
    op.add_column(
        "licenses",
        sa.Column("restricted_until", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_licenses_restricted_until", "licenses", ["restricted_until"], unique=False
    )

    op.create_table(
        "security_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("event_id", sa.String(length=36), nullable=False),
        sa.Column("license_id", sa.Integer(), nullable=True),
        sa.Column("session_id", sa.String(length=64), nullable=True),
        sa.Column("level", sa.Integer(), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("rule", sa.String(length=64), nullable=False),
        sa.Column("reason", sa.String(length=255), nullable=False),
        sa.Column("ip", sa.String(length=45), nullable=False),
        sa.Column("user_agent", sa.String(length=256), nullable=False),
        sa.Column(
            "status",
            sa.String(length=16),
            nullable=False,
            server_default="CONFIRMED",
        ),
        sa.Column("action_taken", sa.String(length=32), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_security_events"),
        sa.ForeignKeyConstraint(
            ["license_id"], ["licenses.id"], name="fk_security_events_license_id",
            ondelete="SET NULL"
        ),
    )
    op.create_index(
        "ix_security_events_event_id", "security_events", ["event_id"], unique=True
    )
    op.create_index(
        "ix_security_events_license_id", "security_events", ["license_id"], unique=False
    )
    op.create_index(
        "ix_security_events_session_id", "security_events", ["session_id"], unique=False
    )
    op.create_index(
        "ix_security_events_level_created_at",
        "security_events",
        ["level", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_security_events_license_id_created_at",
        "security_events",
        ["license_id", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    """Drop the security_events table and restore licenses to its prior state."""
    op.drop_index("ix_security_events_license_id_created_at", table_name="security_events")
    op.drop_index("ix_security_events_level_created_at", table_name="security_events")
    op.drop_index("ix_security_events_session_id", table_name="security_events")
    op.drop_index("ix_security_events_license_id", table_name="security_events")
    op.drop_index("ix_security_events_event_id", table_name="security_events")
    op.drop_table("security_events")

    op.drop_index("ix_licenses_restricted_until", table_name="licenses")
    op.drop_column("licenses", "restricted_until")
