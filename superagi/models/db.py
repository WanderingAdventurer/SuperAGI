import os
from sqlalchemy import create_engine
from superagi.config.config import get_config
from urllib.parse import urlparse
from superagi.lib.logger import logger

engine = None


def connect_db():
    global engine
    if engine is not None:
        return engine

    db_url = get_config('DB_URL', None)

    # Fallback logic if DB_URL not explicitly set
    if db_url is None:
        db_host = get_config('DB_HOST')
        db_username = get_config('DB_USERNAME')
        db_password = get_config('DB_PASSWORD')
        db_name = get_config('DB_NAME')

        # Fallback to environment if config returns None
        if not all([db_host, db_username, db_password, db_name]):
            db_url = os.getenv("DATABASE_URL")

        else:
            db_url = f"postgresql://{db_username}:{db_password}@{db_host}/{db_name}"

    if not db_url:
        raise ValueError("DATABASE URL could not be determined. Check your environment variables or config.")

    engine = create_engine(
        db_url,
        pool_size=20,
        max_overflow=50,
        pool_timeout=30,
        pool_recycle=1800,
        pool_pre_ping=False
    )

    # Test the connection
    try:
        connection = engine.connect()
        logger.info("Connected to the database! @ " + db_url)
        connection.close()
    except Exception as e:
        logger.error(f"Unable to connect to the database: {e}")

    return engine
