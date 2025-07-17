"""
Database utilities and SQLAlchemy models for PostgreSQL integration.
To be expanded with ORM models as the app grows.
"""

import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.environ.get("POSTGRES_URL") or os.environ.get("DATABASE_URL")
Base = declarative_base()
engine = create_async_engine(DATABASE_URL, echo=True, future=True)
SessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# PUBLIC_INTERFACE
def get_db():
    """Yields an async session to the database."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
