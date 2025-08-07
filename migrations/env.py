from logging.config import fileConfig
import os
from urllib.parse import urlparse

from sqlalchemy import engine_from_config, pool
from alembic import context

from superagi.models.base_model import DBBaseModel
from superagi.config.config import get_config

# Alembic config object
config = context.config

# Set up logging from config file
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Target metadata for 'autogenerate'
target_metadata = DBBaseModel.metadata

def construct_db_url():
    """Constructs a valid SQLAlchemy database URL."""
    db_url = get_config('DB_URL', None)

    if db_url:
        parsed = urlparse(db_url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    # Fallback if DB_URL isn't set
    db_host = get_config('DB_HOST', 'localhost')
    db_user = get_config('DB_USERNAME', 'postgres')
    db_pass = get_config('DB_PASSWORD', '')
    db_name = get_config('DB_NAME', 'postgres')

    return f"postgresql://{db_user}:{db_pass}@{db_host}/{db_name}"

def run_migrations_offline() -> None:
    """Run migrations without DB engine (offline mode)."""
    url = construct_db_url()
    config.set_main_option("sqlalchemy.url", url)

    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online() -> None:
    """Run migrations with DB engine (online mode)."""
    url = construct_db_url()
    config.set_main_option("sqlalchemy.url", url)

    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()

# Entry point
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
