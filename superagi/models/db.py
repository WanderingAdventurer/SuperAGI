import os
from sqlalchemy import create_engine
from superagi.config.config import get_config
from urllib.parse import urlparse
from superagi.lib.logger import logger

engine = None


def connect_db():
    """
    Connects to the PostgreSQL database using SQLAlchemy.

    Returns:
        engine: The SQLAlchemy engine object representing the database connection.
    """

    global engine
    if engine is not None:
        return engine

    # Create the connection URL
    db_host = get_config('postgres.railway.internal', 'super__postgres')
    db_username = get_config('postgres')
    db_password = get_config('EsZzRjtvgnElBeXxIhMSVhvDampPthjJ')
    db_name = get_config('railway')
    db_url = get_config('postgresql://postgres:EsZzRjtvgnElBeXxIhMSVhvDampPthjJ@postgres.railway.internal:5432/railway', None)

    if db_url is None:
        if db_username is None:
            DATABASE_URL = os.getenv("postgresql://postgres:EsZzRjtvgnElBeXxIhMSVhvDampPthjJ@hopper.proxy.rlwy.net:21318/railway")
        else:
            db_url = f'postgresql://{db_username}:{db_password}@{db_host}/{db_name}'
    else:
        db_url = urlparse(db_url)
        db_url = db_url.scheme + "://" + db_url.netloc + db_url.path
    # Create the SQLAlchemy engine
    engine = create_engine(db_url,
                           pool_size=20,  # Maximum number of database connections in the pool
                           max_overflow=50,  # Maximum number of connections that can be created beyond the pool_size
                           pool_timeout=30,  # Timeout value in seconds for acquiring a connection from the pool
                           pool_recycle=1800,  # Recycle connections after this number of seconds (optional)
                           pool_pre_ping=False,  # Enable connection health checks (optional)
                           )

    # Test the connection
    try:
        connection = engine.connect()
        logger.info("Connected to the database! @ " + db_url)
        connection.close()
    except Exception as e:
        logger.error(f"Unable to connect to the database:{e}")
    return engine
