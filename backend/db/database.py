from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

# SQLite for demo; swap URL for Postgres in prod — schema is compatible
DATABASE_URL = "sqlite:///./auth.db"

engine = create_engine(
    DATABASE_URL,
    # SQLite-specific: check_same_thread=False allows use across request threads
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    """FastAPI dependency: yields a DB session, always closes it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
