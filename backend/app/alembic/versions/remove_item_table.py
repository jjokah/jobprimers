"""Remove item table

Revision ID: remove_item_table_001
Revises: 1a31ce608336
Create Date: 2024-12-19 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
import sqlmodel.sql.sqltypes


# revision identifiers, used by Alembic.
revision = 'remove_item_table_001'
down_revision = '1a31ce608336'
branch_labels = None
depends_on = None


def upgrade():
    # Drop the item table and its constraints
    op.drop_table('item')


def downgrade():
    # Recreate the item table (this is just for rollback purposes)
    op.create_table(
        'item',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('title', sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column('description', sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column('owner_id', sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(['owner_id'], ['user.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
