"""
SQLite Database Unit Tests using unittest with Isolated Temporary Database
"""

import unittest
import os
import shutil
import tempfile
from unittest.mock import patch
from rdrs.app.database.db import get_db_connection, init_db


class TestDatabaseORM(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="rdrs_test_db_iso_")
        self.temp_db_path = os.path.join(self.temp_dir, "isolated_rdrs.db")
        self.db_patcher = patch("rdrs.app.database.db.DB_PATH", self.temp_db_path)
        self.db_patcher.start()
        init_db()

    def tearDown(self):
        self.db_patcher.stop()
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_sqlite_insert_and_query(self):
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO file_events (timestamp, event_type, file_path, extension, entropy)
            VALUES (?, ?, ?, ?, ?)
        """, ("2026-01-24T10:00:00", "modified", "data/sandbox/test_db.docx", ".docx", 4.12))
        conn.commit()

        cur.execute("SELECT * FROM file_events WHERE file_path = ?", ("data/sandbox/test_db.docx",))
        row = cur.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["entropy"], 4.12)
        conn.close()


if __name__ == '__main__':
    unittest.main()
