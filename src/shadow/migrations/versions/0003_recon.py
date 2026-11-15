"""Indexed reconnaissance inventory, approvals and immutable observations."""
from alembic import op
import sqlalchemy as sa

revision='0003_recon'
down_revision='0002_workspaces'
branch_labels=None
depends_on=None

def upgrade():
    op.create_table('recon_assets',sa.Column('id',sa.String(36),primary_key=True),sa.Column('engagement',sa.String(36),sa.ForeignKey('engagements.id'),nullable=False),sa.Column('host',sa.String(253),nullable=False),sa.Column('state',sa.String(30),nullable=False),sa.Column('body',sa.Text(),nullable=False),sa.Column('updated',sa.String(40),nullable=False),sa.UniqueConstraint('engagement','host'))
    op.create_index('ix_recon_assets_engagement_state_host','recon_assets',['engagement','state','host'])
    op.create_table('recon_runs',sa.Column('id',sa.String(36),primary_key=True),sa.Column('engagement',sa.String(36),sa.ForeignKey('engagements.id'),nullable=False),sa.Column('status',sa.String(30),nullable=False),sa.Column('body',sa.Text(),nullable=False),sa.Column('created',sa.String(40),nullable=False),sa.Column('updated',sa.String(40),nullable=False))
    op.create_index('ix_recon_runs_engagement_created','recon_runs',['engagement','created'])
    op.create_table('recon_snapshots',sa.Column('run_id',sa.String(36),sa.ForeignKey('recon_runs.id'),primary_key=True),sa.Column('host',sa.String(253),primary_key=True),sa.Column('body',sa.Text(),nullable=False))
    op.create_table('recon_targets',sa.Column('run_id',sa.String(36),sa.ForeignKey('recon_runs.id'),primary_key=True),sa.Column('host',sa.String(253),primary_key=True))

def downgrade():
    raise RuntimeError('Destructive downgrade disabled; use an explicitly selected backup.')
