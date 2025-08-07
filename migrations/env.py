from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context
from urllib.parse import urlparse

# Alembic Config object
config = context.config

# Setup logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import models and metadata
from superagi.models.base_model import DBBaseModel
target_metadata = DBBaseModel.metadata
from superagi.models import *

# --- HARDCODED DB URL FOR DEPLOYMENT STABILITY ---
def construct_db_url():
    return "postgresql://postgres:EsZzRjtvgnElBeXxIhMSVhvDampPthjJ@postgres.railway.internal:5432/railway"

# -----------------------
# OFFLINE MIGRATION MODE
# -----------------------
def run_migrations_offline() -> None:
    db_url = construct_db_url()
    config.set_main_option("sqlalchemy.url", db_url)

    context.configure(
        url=db_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

# -----------------------
# ONLINE MIGRATION MODE
# -----------------------
def run_migrations_online() -> None:
    db_url = construct_db_url()
    config.set_main_option("sqlalchemy.url", db_url)

    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()

# -----------------------
# EXECUTION ENTRYPOINT
# -----------------------
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
