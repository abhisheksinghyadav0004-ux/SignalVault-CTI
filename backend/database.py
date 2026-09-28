import os
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DATABASE_PATH = BASE_DIR / "database" / "signalvault.db"

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{DEFAULT_DATABASE_PATH.as_posix()}",
)

engine_options = {}

if DATABASE_URL.startswith("sqlite"):
    engine_options["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_options)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_database_session():
    database_session = SessionLocal()

    try:
        yield database_session
    finally:
        database_session.close()


def initialize_database():
    from backend import models

    Base.metadata.create_all(bind=engine)

    # SQLite does not update existing tables when ORM columns are added.
    if DATABASE_URL.startswith("sqlite"):
        with engine.begin() as connection:
            existing_columns = {
                row[1]
                for row in connection.execute(text("PRAGMA table_info(indicators)"))
            }
            additions = {
                "analyst_note": "TEXT NOT NULL DEFAULT ''",
                "confidence": "VARCHAR(16) NOT NULL DEFAULT 'Unassessed'",
                "disposition": "VARCHAR(24) NOT NULL DEFAULT 'Open'",
            }
            for name, definition in additions.items():
                if name not in existing_columns:
                    connection.execute(
                        text(f"ALTER TABLE indicators ADD COLUMN {name} {definition}")
                    )
