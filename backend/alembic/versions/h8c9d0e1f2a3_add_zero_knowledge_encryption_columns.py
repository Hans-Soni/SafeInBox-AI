"""add_zero_knowledge_encryption_columns

Revision ID: h8c9d0e1f2a3
Revises: g7b8c9d0e1f2
Create Date: 2026-11-21 02:50:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'h8c9d0e1f2a3'
down_revision: Union[str, Sequence[str], None] = 'g7b8c9d0e1f2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add is_encrypted and encrypted_payload columns for zero-knowledge client-side encryption."""
    with op.batch_alter_table('url_clicks', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_encrypted', sa.Boolean(), nullable=False, server_default=sa.text('false')))
        batch_op.add_column(sa.Column('encrypted_payload', sa.Text(), nullable=True))

    with op.batch_alter_table('security_digest_logs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_encrypted', sa.Boolean(), nullable=False, server_default=sa.text('false')))
        batch_op.add_column(sa.Column('encrypted_payload', sa.Text(), nullable=True))


def downgrade() -> None:
    """Remove zero-knowledge encryption columns."""
    with op.batch_alter_table('security_digest_logs', schema=None) as batch_op:
        batch_op.drop_column('encrypted_payload')
        batch_op.drop_column('is_encrypted')

    with op.batch_alter_table('url_clicks', schema=None) as batch_op:
        batch_op.drop_column('encrypted_payload')
        batch_op.drop_column('is_encrypted')
