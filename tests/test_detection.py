"""
Detection Engine Unit Tests using unittest with Isolated Temp Storage
"""

import os
import shutil
import tempfile
import unittest
from datetime import datetime
from unittest.mock import patch
from rdrs.app.core.config import config
from rdrs.app.database.db import init_db, get_db_connection
from rdrs.app.detectors.detection_engine import DetectionEngine


class TestDetectionEngine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="rdrs_test_det_")
        self.temp_db_path = os.path.join(self.temp_dir, "det.db")
        self.temp_sandbox = os.path.join(self.temp_dir, "sandbox")
        self.temp_quarantine = os.path.join(self.temp_dir, "quarantine")
        os.makedirs(self.temp_sandbox, exist_ok=True)
        os.makedirs(self.temp_quarantine, exist_ok=True)

        self.orig_watch_paths = config._data["monitoring"]["watch_paths"]
        self.orig_quarantine_dir = config._data["quarantine"]["storage_dir"]
        config._data["monitoring"]["watch_paths"] = [self.temp_sandbox]
        config._data["quarantine"]["storage_dir"] = self.temp_quarantine

        self.db_patcher = patch("rdrs.app.database.db.DB_PATH", self.temp_db_path)
        self.db_patcher.start()
        init_db()

    def tearDown(self):
        self.db_patcher.stop()
        config._data["monitoring"]["watch_paths"] = self.orig_watch_paths
        config._data["quarantine"]["storage_dir"] = self.orig_quarantine_dir
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_detection_engine_normal_events(self):
        engine = DetectionEngine()
        now = datetime.now().isoformat()
        events = [
            {"timestamp": now, "event_type": "modified", "file_path": "test1.txt", "entropy": 3.2},
            {"timestamp": now, "event_type": "created", "file_path": "test2.txt", "entropy": 4.1}
        ]
        result = engine.analyze_events(events)
        self.assertTrue(result["threat_score"] < 40)
        self.assertEqual(result["severity"], "Normal")

    def test_single_high_entropy_file_does_not_false_escalate(self):
        engine = DetectionEngine()
        now = datetime.now().isoformat()
        events = [
            {"timestamp": now, "event_type": "created", "file_path": "archive.zip", "entropy": 7.85}
        ]
        result = engine.analyze_events(events)
        self.assertEqual(result["threat_score"], 25)
        self.assertEqual(result["severity"], "Normal")

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as cnt FROM alerts")
        self.assertEqual(cur.fetchone()["cnt"], 0)
        conn.close()

    def test_detection_engine_critical_ransomware_pattern(self):
        engine = DetectionEngine()
        now = datetime.now().isoformat()
        events = [
            {
                "timestamp": now,
                "event_type": "modified",
                "file_path": os.path.join(self.temp_sandbox, f"file_{i}.locked"),
                "entropy": 7.95
            } for i in range(20)
        ]
        events.extend([
            {
                "timestamp": now,
                "event_type": "renamed",
                "file_path": os.path.join(self.temp_sandbox, f"file_{i}.txt"),
                "entropy": 7.95
            } for i in range(10)
        ])

        process_info = {"pid": 8420, "name": "python.exe", "cpu_percent": 88.5, "is_suspicious": True}
        result = engine.analyze_events(events, process_info=process_info)

        self.assertTrue(result["threat_score"] >= 70)
        self.assertEqual(result["severity"], "Critical")
        self.assertIn("Rapid encryption-like activity", result["detection_signals"])
        self.assertIn("Mass file renaming", result["detection_signals"])


if __name__ == '__main__':
    unittest.main()
