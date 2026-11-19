"""add_security_digest_logs_table

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-11-03 01:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3d4e5f6a7b8'
down_revision: Union[str, Sequence[str], None] = 'b2c3d4e5f6a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create security_digest_logs table and its indexes."""
    op.create_table(
        'security_digest_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_email', sa.String(length=255), nullable=False),
        sa.Column('period_start', sa.String(length=64), nullable=False),
        sa.Column('period_end', sa.String(length=64), nullable=False),
        sa.Column('total_emails', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('threat_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('click_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('dispatch_status', sa.String(length=32), nullable=False, server_default='sent'),
        sa.Column('delivery_note', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_security_digest_logs_id'), 'security_digest_logs', ['id'], unique=False)
    op.create_index(op.f('ix_security_digest_logs_user_email'), 'security_digest_logs', ['user_email'], unique=False)


def downgrade() -> None:
    """Drop security_digest_logs table and indexes."""
    op.drop_index(op.f('ix_security_digest_logs_user_email'), table_name='security_digest_logs')
    op.drop_index(op.f('ix_security_digest_logs_id'), table_name='security_digest_logs')
    op.drop_table('security_digest_logs')

