"""add_user_index_id_tracking

Revision ID: g7b8c9d0e1f2
Revises: f6a7b8c9d0e1
Create Date: 2026-11-20 18:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'g7b8c9d0e1f2'
down_revision: Union[str, Sequence[str], None] = 'f6a7b8c9d0e1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add unique index_id to users and user_index_id tracking across logs."""
    # 1. users table
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('index_id', sa.String(length=64), nullable=True))
        batch_op.create_index('ix_users_index_id', ['index_id'], unique=True)

    # 2. url_clicks table
    with op.batch_alter_table('url_clicks', schema=None) as batch_op:
        batch_op.add_column(sa.Column('user_index_id', sa.String(length=64), nullable=True))
        batch_op.create_index('ix_url_clicks_user_index_id', ['user_index_id'], unique=False)

    # 3. security_digest_logs table
    with op.batch_alter_table('security_digest_logs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('user_index_id', sa.String(length=64), nullable=True))
        batch_op.create_index('ix_security_digest_logs_user_index_id', ['user_index_id'], unique=False)

    # 4. terms_consents table
    with op.batch_alter_table('terms_consents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('user_index_id', sa.String(length=64), nullable=True))
        batch_op.create_index('ix_terms_consents_user_index_id', ['user_index_id'], unique=False)

    # 5. scan_audit_logs table
    with op.batch_alter_table('scan_audit_logs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('user_email', sa.String(length=255), nullable=True))
        batch_op.create_index('ix_scan_audit_logs_user_email', ['user_email'], unique=False)
        batch_op.add_column(sa.Column('user_index_id', sa.String(length=64), nullable=True))
        batch_op.create_index('ix_scan_audit_logs_user_index_id', ['user_index_id'], unique=False)


def downgrade() -> None:
    """Revert user_index_id tracking columns."""
    with op.batch_alter_table('scan_audit_logs', schema=None) as batch_op:
        batch_op.drop_index('ix_scan_audit_logs_user_index_id')
        batch_op.drop_column('user_index_id')
        batch_op.drop_index('ix_scan_audit_logs_user_email')
        batch_op.drop_column('user_email')

    with op.batch_alter_table('terms_consents', schema=None) as batch_op:
        batch_op.drop_index('ix_terms_consents_user_index_id')
        batch_op.drop_column('user_index_id')

    with op.batch_alter_table('security_digest_logs', schema=None) as batch_op:
        batch_op.drop_index('ix_security_digest_logs_user_index_id')
        batch_op.drop_column('user_index_id')

    with op.batch_alter_table('url_clicks', schema=None) as batch_op:
        batch_op.drop_index('ix_url_clicks_user_index_id')
        batch_op.drop_column('user_index_id')

    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_index('ix_users_index_id')
        batch_op.drop_column('index_id')
