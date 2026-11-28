"""add_community_threat_signals_table

Revision ID: j0e1f2a3b4c5
Revises: i9d0e1f2a3b4
Create Date: 2026-11-28 17:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'j0e1f2a3b4c5'
down_revision: Union[str, Sequence[str], None] = 'i9d0e1f2a3b4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create community_threat_signals table and add skeleton_hash column to feedback_records."""
    op.create_table(
        'community_threat_signals',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('target_hash', sa.String(length=64), nullable=False),
        sa.Column('target_type', sa.String(length=16), nullable=False),
        sa.Column('threat_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('safe_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_reported_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_community_threat_signals_id', 'community_threat_signals', ['id'], unique=False)
    op.create_index('ix_community_threat_signals_target_hash', 'community_threat_signals', ['target_hash'], unique=True)
    op.create_index('ix_community_threat_signals_target_type', 'community_threat_signals', ['target_type'], unique=False)

    # Add skeleton_hash column to feedback_records if not present
    op.add_column('feedback_records', sa.Column('skeleton_hash', sa.String(length=64), nullable=True))
    op.create_index('ix_feedback_records_skeleton_hash', 'feedback_records', ['skeleton_hash'], unique=False)


def downgrade() -> None:
    """Drop community_threat_signals table and drop skeleton_hash column."""
    op.drop_index('ix_feedback_records_skeleton_hash', table_name='feedback_records')
    op.drop_column('feedback_records', 'skeleton_hash')
    op.drop_index('ix_community_threat_signals_target_type', table_name='community_threat_signals')
    op.drop_index('ix_community_threat_signals_target_hash', table_name='community_threat_signals')
    op.drop_index('ix_community_threat_signals_id', table_name='community_threat_signals')
    op.drop_table('community_threat_signals')
