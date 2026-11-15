"""Foundation: explicit authorizations and audit records."""
from alembic import op
import sqlalchemy as sa
revision='0001_foundation'
down_revision=None
branch_labels=None
depends_on=None

def upgrade():
    op.create_table('audit_events',sa.Column('id',sa.Integer(),primary_key=True),sa.Column('timestamp',sa.String(40),nullable=False),sa.Column('action',sa.String(100),nullable=False),sa.Column('details',sa.Text(),nullable=False))
    op.create_table('engagements',sa.Column('id',sa.String(36),primary_key=True),sa.Column('name',sa.String(150),nullable=False),sa.Column('scope',sa.Text(),nullable=False),sa.Column('exclusions',sa.Text(),nullable=False),sa.Column('authorization',sa.Text(),nullable=False),sa.Column('rules',sa.Text(),nullable=False),sa.Column('created',sa.String(40),nullable=False))

def downgrade():
    raise RuntimeError('Destructive downgrade is disabled. Restore an explicitly selected backup instead.')
