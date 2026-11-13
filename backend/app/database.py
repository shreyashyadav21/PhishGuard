from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker
from .config import settings

def normalize_database_url(database_url: str) -> str:
    if database_url.startswith("postgres://"):
        return database_url.replace("postgres://", "postgresql+psycopg://", 1)
    if database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+psycopg://", 1)
    return database_url


# SQLite connection with thread checking disabled for FastAPI
database_url = normalize_database_url(settings.DATABASE_URL)
connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}

engine = create_engine(
    database_url,
    connect_args=connect_args,
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def run_migrations():
    inspector = inspect(engine)
    if not inspector.has_table("scans"):
        return

    existing_cols = {column["name"] for column in inspector.get_columns("scans")}
    migrations = {
        "gmail_message_id": "VARCHAR(100)",
        "account_email": "VARCHAR(255)",
        "gmail_thread_id": "VARCHAR(100)",
    }

    with engine.begin() as conn:
        for column_name, column_type in migrations.items():
            if column_name not in existing_cols:
                conn.execute(text(
                    f"ALTER TABLE scans ADD COLUMN {column_name} {column_type}"
                ))

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
