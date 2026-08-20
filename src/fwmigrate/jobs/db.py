from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fwmigrate.jobs.models import Base

# Enterprise setups should provide a connection string pointing to PostgreSQL.
# For local dev, we default to SQLite.
DEFAULT_DB_URL = "sqlite:///fwmigrate.db"

def get_engine(db_url: str = DEFAULT_DB_URL):
    # In production with PostgreSQL, add pool_size and max_overflow
    return create_engine(db_url, echo=False)

def get_session_factory(engine):
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db(engine):
    """
    Creates all tables.
    In a real production environment, this should be handled by Alembic migrations.
    """
    Base.metadata.create_all(bind=engine)
