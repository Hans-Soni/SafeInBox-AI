"""add_terms_consents_table

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-11-01 13:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, Sequence[str], None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create terms_consents table and its indexes."""
    op.create_table(
        'terms_consents',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('ip_address', sa.String(length=64), nullable=False),
        sa.Column('mac_address', sa.String(length=128), nullable=True),
        sa.Column('terms_version', sa.String(length=32), nullable=False, server_default='1.0.0'),
        sa.Column('user_agent', sa.String(length=512), nullable=True),
        sa.Column('agreed_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_terms_consents_id'), 'terms_consents', ['id'], unique=False)
    op.create_index(op.f('ix_terms_consents_email'), 'terms_consents', ['email'], unique=False)
    op.create_index(op.f('ix_terms_consents_user_id'), 'terms_consents', ['user_id'], unique=False)


def downgrade() -> None:
    """Drop terms_consents table and indexes."""
    op.drop_index(op.f('ix_terms_consents_user_id'), table_name='terms_consents')
    op.drop_index(op.f('ix_terms_consents_email'), table_name='terms_consents')
    op.drop_index(op.f('ix_terms_consents_id'), table_name='terms_consents')
    op.drop_table('terms_consents')

