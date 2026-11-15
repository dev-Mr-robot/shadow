"""Indexed defensive event evidence and ingestion deduplication."""
from alembic import op
import sqlalchemy as sa
revision='0004_soc'
down_revision='0003_recon'
branch_labels=None
depends_on=None
def upgrade():
    op.create_table('soc_events',sa.Column('id',sa.String(36),primary_key=True),sa.Column('timestamp',sa.String(40),nullable=False),sa.Column('source_id',sa.String(36),nullable=False),sa.Column('event_hash',sa.String(64),nullable=False,unique=True),sa.Column('event_type',sa.String(60),nullable=False),sa.Column('host',sa.String(253),nullable=False),sa.Column('src_ip',sa.String(60),nullable=False),sa.Column('dst_ip',sa.String(60),nullable=False),sa.Column('username',sa.String(200),nullable=False),sa.Column('body',sa.Text(),nullable=False))
    for column in ['timestamp','source_id','event_type','host','src_ip','dst_ip','username']:op.create_index('ix_soc_events_'+column,'soc_events',[column])
    op.create_index('ix_soc_event_type_time','soc_events',['event_type','timestamp'])
def downgrade():raise RuntimeError('Destructive downgrade disabled; use an explicitly selected backup.')
