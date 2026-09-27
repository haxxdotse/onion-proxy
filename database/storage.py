import sqlite3
from collections.abc import Iterable

from config import DATABASE_PATH


def connect() -> sqlite3.Connection:
    return sqlite3.connect(
        DATABASE_PATH
    )


def initialize() -> None:

    with connect() as connection:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application TEXT NOT NULL,
                domain TEXT NOT NULL,
                findings TEXT NOT NULL,
                action TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)


def save_event(
    application: str,
    domain: str,
    findings: Iterable[str],
    action: str,
) -> None:

    findings_text = ", ".join(
        findings
    )

    with connect() as connection:

        connection.execute("""
            INSERT INTO events (
                application,
                domain,
                findings,
                action
            )
            VALUES (?, ?, ?, ?)
        """, (
            application,
            domain,
            findings_text,
            action,
        ))