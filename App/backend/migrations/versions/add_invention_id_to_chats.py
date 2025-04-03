"""add invention_id to chats

Revision ID: 20250403_add_invention_id_to_chats
Revises: 20250327_initial_schema
Create Date: 2025-04-03 14:30:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '20250403_add_invention_id_to_chats'
down_revision = '20250327_initial_schema'
branch_labels = None
depends_on = None

def upgrade():
    # Add invention_id column
    op.add_column('chats', sa.Column('invention_id', sa.Integer(), nullable=False))
    
    # Add foreign key constraint
    op.create_foreign_key(
        'fk_chats_invention_id',
        'chats', 'inventions',
        ['invention_id'], ['id'],
        ondelete='CASCADE'
    )

def downgrade():
    # Remove foreign key constraint
    op.drop_constraint('fk_chats_invention_id', 'chats', type_='foreignkey')
    
    # Remove invention_id column
    op.drop_column('chats', 'invention_id') 