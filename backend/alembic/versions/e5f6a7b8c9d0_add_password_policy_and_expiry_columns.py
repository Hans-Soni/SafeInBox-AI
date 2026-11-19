"""add_password_policy_and_expiry_columns

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-11-04 16:45:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e5f6a7b8c9d0'
down_revision: Union[str, Sequence[str], None] = 'd4e5f6a7b8c9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add password rotation and security policy columns to users table."""
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('password_changed_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))
        batch_op.add_column(sa.Column('password_history', sa.JSON(), server_default='[]', nullable=False))
        batch_op.add_column(sa.Column('failed_login_attempts', sa.Integer(), server_default='0', nullable=False))
        batch_op.add_column(sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    """Remove password policy columns from users table."""
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('locked_until')
        batch_op.drop_column('failed_login_attempts')
        batch_op.drop_column('password_history')
        batch_op.drop_column('password_changed_at')

