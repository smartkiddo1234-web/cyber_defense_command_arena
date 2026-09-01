"""
AI Tactical Command And Deployment Simulator — Database Foundation

Provides SQLite database initialization and connection management.
This module establishes the foundation that later phases will extend
with incident, event, and telemetry schemas.
"""

import os
import sqlite3
from contextlib import contextmanager


class DatabaseManager:
    """Manages SQLite database connections and initialization."""

    def __init__(self, database_path):
        self.database_path = database_path
        self._ensure_database_directory()

    def _ensure_database_directory(self):
        """Create the database directory if it does not exist."""
        db_dir = os.path.dirname(self.database_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

    def get_connection(self):
        """Return a new database connection."""
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @contextmanager
    def get_db(self):
        """Context manager that yields a connection and auto-closes."""
        conn = self.get_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self):
        """
        Initialize the database with the base schema.

        Phase 1 creates only the metadata table to verify the database
        is operational. Later phases will add tables for:
        - simulated assets and infrastructure
        - threat events and incidents
        - evidence and confidence records
        - deception actions
        - defense unit states
        - commander decisions
        """
        with self.get_db() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS meta (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            # Record schema version for future migrations
            conn.execute("""
                INSERT OR REPLACE INTO meta (key, value)
                VALUES ('schema_version', '0.1.0')
            """)
            conn.execute("""
                INSERT OR REPLACE INTO meta (key, value)
                VALUES ('phase', 'Phase 1 — Foundation')
            """)

    def get_schema_version(self):
        """Return the current schema version, or None if unavailable."""
        try:
            with self.get_db() as conn:
                row = conn.execute(
                    "SELECT value FROM meta WHERE key = 'schema_version'"
                ).fetchone()
                return row["value"] if row else None
        except sqlite3.OperationalError:
            return None
