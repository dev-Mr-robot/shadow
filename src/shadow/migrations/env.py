from alembic import context
from shadow.database import Base

connection=context.config.attributes.get('connection')
if connection is None:raise RuntimeError('Migrations must be run through shadow init/upgrade')
context.configure(connection=connection,target_metadata=Base.metadata,render_as_batch=True)
with context.begin_transaction():context.run_migrations()
