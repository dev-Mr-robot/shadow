"""Persistent conversations, memories, evidence, findings, reports and approvals."""
from alembic import op
import sqlalchemy as sa
revision='0002_workspaces'
down_revision='0001_foundation'
branch_labels=None
depends_on=None

def upgrade():
    op.create_table('workspace_records',sa.Column('id',sa.String(36),primary_key=True),sa.Column('kind',sa.String(60),nullable=False),sa.Column('parent',sa.String(36),nullable=True),sa.Column('body',sa.Text(),nullable=False),sa.Column('created',sa.String(40),nullable=False),sa.Column('updated',sa.String(40),nullable=False))
    op.create_index('ix_workspace_records_kind','workspace_records',['kind'])
    op.create_index('ix_records_kind_parent_created','workspace_records',['kind','parent','created'])

def downgrade():raise RuntimeError('Destructive downgrade disabled; restore an explicitly selected backup.')
