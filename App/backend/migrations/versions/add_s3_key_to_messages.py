"""add s3_key to messages

Revision ID: 20250403_add_s3_key_to_messages
Revises: 20250327_initial_schema
Create Date: 2025-04-03 14:05:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '20250403_add_s3_key_to_messages'
down_revision = '20250327_initial_schema'
branch_labels = None
depends_on = None

def upgrade():
    # Add s3_key column to messages table
    op.add_column('messages', sa.Column('s3_key', sa.String(255), nullable=True))

def downgrade():
    # Remove s3_key column from messages table
    op.drop_column('messages', 's3_key') 