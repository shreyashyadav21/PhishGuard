from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
from .config import settings

# SQLite connection with thread checking disabled for FastAPI
connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def run_migrations():
    """
    Safely executes schema migrations on SQLite/PostgreSQL to add
    new columns to existing tables without data loss.
    """
    with engine.connect() as conn:
        # Check columns in 'scans' table
        try:
            result = conn.execute(text("PRAGMA table_info(scans)"))
            existing_cols = [row[1] for row in result.fetchall()]
            if existing_cols:
                if "gmail_message_id" not in existing_cols:
                    conn.execute(text("ALTER TABLE scans ADD COLUMN gmail_message_id VARCHAR(100)"))
                    conn.commit()
                if "account_email" not in existing_cols:
                    conn.execute(text("ALTER TABLE scans ADD COLUMN account_email VARCHAR(255)"))
                    conn.commit()
                if "gmail_thread_id" not in existing_cols:
                    conn.execute(text("ALTER TABLE scans ADD COLUMN gmail_thread_id VARCHAR(100)"))
                    conn.commit()
        except Exception:
            pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
