"""add_email_otp_verifications_table

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-11-09 22:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f6a7b8c9d0e1'
down_revision: Union[str, Sequence[str], None] = 'e5f6a7b8c9d0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create email_otp_verifications table."""
    op.create_table(
        'email_otp_verifications',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('otp_hash', sa.String(length=255), nullable=False),
        sa.Column('salt', sa.String(length=64), nullable=False),
        sa.Column('pending_data', sa.JSON(), nullable=False),
        sa.Column('attempts_left', sa.Integer(), server_default='3', nullable=False),
        sa.Column('resend_available_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('email_otp_verifications', schema=None) as batch_op:
        batch_op.create_index('ix_email_otp_verifications_id', ['id'], unique=False)
        batch_op.create_index('ix_email_otp_verifications_email', ['email'], unique=True)


def downgrade() -> None:
    """Drop email_otp_verifications table."""
    with op.batch_alter_table('email_otp_verifications', schema=None) as batch_op:
        batch_op.drop_index('ix_email_otp_verifications_email')
        batch_op.drop_index('ix_email_otp_verifications_id')
    op.drop_table('email_otp_verifications')

