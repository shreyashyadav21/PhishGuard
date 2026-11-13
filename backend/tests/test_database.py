import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.pool import StaticPool

from app import database
from app.database import normalize_database_url


@pytest.mark.parametrize(
    ("database_url", "expected_url"),
    [
        (
            "postgres://user:pass@host/db?sslmode=require",
            "postgresql+psycopg://user:pass@host/db?sslmode=require",
        ),
        (
            "postgresql://user:pass@host/db?sslmode=require",
            "postgresql+psycopg://user:pass@host/db?sslmode=require",
        ),
    ],
)
def test_normalize_postgres_database_url(database_url, expected_url):
    assert normalize_database_url(database_url) == expected_url


def test_run_migrations_adds_scan_metadata_columns(monkeypatch):
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    with test_engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE scans (id INTEGER PRIMARY KEY)")

    monkeypatch.setattr(database, "engine", test_engine)
    database.run_migrations()

    columns = {column["name"] for column in inspect(test_engine).get_columns("scans")}
    assert {"gmail_message_id", "account_email", "gmail_thread_id"} <= columns
