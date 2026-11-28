"""add_threat_lsh_signatures_table

Revision ID: k1f2a3b4c5d6
Revises: j0e1f2a3b4c5
Create Date: 2026-11-28 18:20:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'k1f2a3b4c5d6'
down_revision: Union[str, Sequence[str], None] = 'j0e1f2a3b4c5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create threat_lsh_signatures table with indexed band buckets for Tier 2 fuzzy matching."""
    op.create_table(
        'threat_lsh_signatures',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('target_hash', sa.String(length=64), nullable=False),
        sa.Column('target_type', sa.String(length=16), nullable=False),
        sa.Column('b0', sa.BigInteger(), nullable=False),
        sa.Column('b1', sa.BigInteger(), nullable=False),
        sa.Column('b2', sa.BigInteger(), nullable=False),
        sa.Column('b3', sa.BigInteger(), nullable=False),
        sa.Column('b4', sa.BigInteger(), nullable=False),
        sa.Column('b5', sa.BigInteger(), nullable=False),
        sa.Column('b6', sa.BigInteger(), nullable=False),
        sa.Column('b7', sa.BigInteger(), nullable=False),
        sa.Column('b8', sa.BigInteger(), nullable=False),
        sa.Column('b9', sa.BigInteger(), nullable=False),
        sa.Column('b10', sa.BigInteger(), nullable=False),
        sa.Column('b11', sa.BigInteger(), nullable=False),
        sa.Column('b12', sa.BigInteger(), nullable=False),
        sa.Column('b13', sa.BigInteger(), nullable=False),
        sa.Column('b14', sa.BigInteger(), nullable=False),
        sa.Column('b15', sa.BigInteger(), nullable=False),
        sa.Column('minhash_sig', sa.String(length=512), nullable=False),
        sa.Column('threat_count', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('safe_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_reported_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_threat_lsh_signatures_id', 'threat_lsh_signatures', ['id'], unique=False)
    op.create_index('ix_threat_lsh_signatures_target_hash', 'threat_lsh_signatures', ['target_hash'], unique=False)
    op.create_index('ix_threat_lsh_signatures_target_type', 'threat_lsh_signatures', ['target_type'], unique=False)
    for b in range(16):
        op.create_index(f'ix_threat_lsh_signatures_b{b}', 'threat_lsh_signatures', [f'b{b}'], unique=False)


def downgrade() -> None:
    """Drop threat_lsh_signatures table and indexes."""
    for b in range(16):
        op.drop_index(f'ix_threat_lsh_signatures_b{b}', table_name='threat_lsh_signatures')
    op.drop_index('ix_threat_lsh_signatures_target_type', table_name='threat_lsh_signatures')
    op.drop_index('ix_threat_lsh_signatures_target_hash', table_name='threat_lsh_signatures')
    op.drop_index('ix_threat_lsh_signatures_id', table_name='threat_lsh_signatures')
    op.drop_table('threat_lsh_signatures')
