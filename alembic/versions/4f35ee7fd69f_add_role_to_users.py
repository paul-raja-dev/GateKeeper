"""add_role_to_users

Revision ID: 4f35ee7fd69f
Revises: 4798461e2b24
Create Date: 2026-07-17 10:44:27.858896

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4f35ee7fd69f'
down_revision: Union[str, Sequence[str], None] = '4798461e2b24'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Create the enum type first — Alembic autogenerate misses this for PostgreSQL
    userrole_enum = sa.Enum('user', 'admin', 'superadmin', name='userrole')
    userrole_enum.create(op.get_bind(), checkfirst=True)

    op.add_column('users', sa.Column(
        'role',
        userrole_enum,
        server_default='user',
        nullable=False,
        comment='RBAC role: user | admin | superadmin',
    ))
    op.alter_column('users', 'is_superuser',
               existing_type=sa.BOOLEAN(),
               comment='Legacy superuser flag — use role field for RBAC instead',
               existing_comment='Admin flag — superusers bypass permission checks',
               existing_nullable=False,
               existing_server_default=sa.text('false'))


def downgrade() -> None:
    """Downgrade schema."""
    op.alter_column('users', 'is_superuser',
               existing_type=sa.BOOLEAN(),
               comment='Admin flag — superusers bypass permission checks',
               existing_comment='Legacy superuser flag — use role field for RBAC instead',
               existing_nullable=False,
               existing_server_default=sa.text('false'))
    op.drop_column('users', 'role')

    # Drop the enum type after the column is removed
    sa.Enum(name='userrole').drop(op.get_bind(), checkfirst=True)

