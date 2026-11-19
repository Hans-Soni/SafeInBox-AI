"""add_url_clicks_table

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-11-04 02:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd4e5f6a7b8c9'
down_revision: Union[str, Sequence[str], None] = 'c3d4e5f6a7b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create url_clicks table and its indexes."""
    op.create_table(
        'url_clicks',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_email', sa.String(length=255), nullable=True),
        sa.Column('url', sa.String(length=4096), nullable=False),
        sa.Column('defanged_url', sa.String(length=4096), nullable=False),
        sa.Column('url_hash', sa.String(length=64), nullable=False),
        sa.Column('email_subject', sa.String(length=255), nullable=True),
        sa.Column('sender', sa.String(length=255), nullable=True),
        sa.Column('risk_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('risk_level', sa.String(length=32), nullable=False, server_default='AUDITED'),
        sa.Column('proceeded', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('source', sa.String(length=64), nullable=False, server_default='email_body_link'),
        sa.Column('clicked_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_url_clicks_id'), 'url_clicks', ['id'], unique=False)
    op.create_index(op.f('ix_url_clicks_user_email'), 'url_clicks', ['user_email'], unique=False)
    op.create_index(op.f('ix_url_clicks_url_hash'), 'url_clicks', ['url_hash'], unique=False)


def downgrade() -> None:
    """Drop url_clicks table and indexes."""
    op.drop_index(op.f('ix_url_clicks_url_hash'), table_name='url_clicks')
    op.drop_index(op.f('ix_url_clicks_user_email'), table_name='url_clicks')
    op.drop_index(op.f('ix_url_clicks_id'), table_name='url_clicks')
    op.drop_table('url_clicks')

