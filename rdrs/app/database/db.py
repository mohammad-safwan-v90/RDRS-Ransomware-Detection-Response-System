"""
SQLite Database Layer for RDRS with WAL mode and alert/incident management
"""

import os
import sqlite3

DB_PATH = "./data/rdrs.db"

def get_db_connection():
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def init_db():
    conn = get_db_connection()
    try:
        cur = conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS file_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            file_path TEXT NOT NULL,
            dest_path TEXT,
            extension TEXT NOT NULL,
            entropy REAL DEFAULT 0.0,
            process_id INTEGER
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS process_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            pid INTEGER NOT NULL,
            name TEXT NOT NULL,
            cpu_percent REAL DEFAULT 0.0,
            memory_percent REAL DEFAULT 0.0,
            num_threads INTEGER DEFAULT 1,
            status TEXT DEFAULT 'running',
            is_suspicious INTEGER DEFAULT 0
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            threat_score INTEGER NOT NULL,
            message TEXT NOT NULL,
            detection_signals TEXT NOT NULL,
            affected_files TEXT NOT NULL,
            status TEXT DEFAULT 'Unacknowledged'
        )
        """)

        # Ensure status column exists in existing alerts table if migrated
        try:
            cur.execute("ALTER TABLE alerts ADD COLUMN status TEXT DEFAULT 'Unacknowledged'")
        except sqlite3.OperationalError:
            pass

        cur.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT UNIQUE NOT NULL,
            timestamp TEXT NOT NULL,
            threat_score INTEGER NOT NULL,
            severity TEXT NOT NULL,
            affected_files_count INTEGER NOT NULL,
            affected_files TEXT NOT NULL,
            process_name TEXT,
            process_pid INTEGER,
            detection_signals TEXT NOT NULL,
            status TEXT DEFAULT 'Contained (Simulation)',
            quarantine_paths TEXT
        )
        """)

        conn.commit()
    finally:
        conn.close()


# Auto init database
init_db()

