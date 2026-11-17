"""
Phase 6 Repeatable End-to-End Integration Test (Real Components in Isolated Temp Workspace)
Exercises Observer/Monitoring -> File Activity (create/modify/rename/high-entropy) ->
Detection Engine -> SQLite Persistence Across Connection Reopen -> Quarantine Containment -> Reports -> Health.
"""

import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from datetime import datetime
from unittest.mock import patch

from rdrs.app.core.config import config
from rdrs.app.database.db import get_db_connection, init_db
from rdrs.app.detectors.detection_engine import DetectionEngine
from rdrs.app.detectors.file_monitor import Observer, RDRSFileEventHandler
from rdrs.app.reports.report_generator import ReportGenerator
import rdrs.app.api.main as api_main


class TestPhase6EndToEndPipeline(unittest.TestCase):
    def setUp(self):
            self.temp_dir = tempfile.mkdtemp(
                prefix="rdrs_p6_e2e_",
                dir=os.getcwd(),
            )
            self.sandbox_dir = os.path.join(self.temp_dir, "sandbox")
            self.quarantine_dir = os.path.join(self.temp_dir, "quarantine")
            self.reports_dir = os.path.join(self.temp_dir, "reports")
            self.db_path = os.path.join(self.temp_dir, "e2e.db")
            self.status_path = os.path.join(self.temp_dir, "status.json")
            os.makedirs(self.sandbox_dir, exist_ok=True)
            os.makedirs(self.quarantine_dir, exist_ok=True)
            os.makedirs(self.reports_dir, exist_ok=True)
            
            self.orig_watch_paths = config._data["monitoring"]["watch_paths"]
            self.orig_quarantine_dir = config._data["quarantine"]["storage_dir"]
            config._data["monitoring"]["watch_paths"] = [self.sandbox_dir]
            config._data["quarantine"]["storage_dir"] = self.quarantine_dir
            
            self.db_patcher = patch("rdrs.app.database.db.DB_PATH", self.db_path)
            self.db_patcher.start()
            init_db()

    def tearDown(self):
        self.db_patcher.stop()
        config._data["monitoring"]["watch_paths"] = self.orig_watch_paths
        config._data["quarantine"]["storage_dir"] = self.orig_quarantine_dir
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_end_to_end_real_monitoring_detection_persistence_and_reports(self):
        with open(self.status_path, "w", encoding="utf-8") as f:
            json.dump({
                "is_monitoring": True,
                "observer_alive": True,
                "pid": os.getpid(),
                "last_heartbeat": datetime.now().isoformat()
            }, f)

        health = api_main.get_real_health(status_file_path=self.status_path)
        self.assertEqual(health["status"], "healthy")
        self.assertTrue(health["database_accessible"])

        captured_events = []
        cap_lock = threading.Lock()

        def on_event(evt):
            with cap_lock:
                captured_events.append(evt)

        handler = RDRSFileEventHandler(watch_dir=self.sandbox_dir, event_callback=on_event)
        from watchdog.observers.polling import PollingObserver
        observer = PollingObserver(timeout=0.2)
        observer.schedule(handler, path=self.sandbox_dir, recursive=True)
        observer.start()

        try:
            # Step 1: Normal file create, modify, rename inside isolated sandbox
            normal_file = os.path.join(self.sandbox_dir, "notes.txt")
            with open(normal_file, "w", encoding="utf-8") as f:
                f.write("Normal readable coursework document line 1.\n")
            time.sleep(0.7)

            with open(normal_file, "a", encoding="utf-8") as f:
                f.write("Modified readable text line 2.\n")
            time.sleep(0.7)

            renamed_normal = os.path.join(self.sandbox_dir, "notes_renamed.txt")
            os.rename(normal_file, renamed_normal)
            time.sleep(0.7)

            # Verify normal activity alone does not trigger false Critical alert
            engine = DetectionEngine()
            with cap_lock:
                normal_snapshot = list(captured_events)
            self.assertGreaterEqual(len(normal_snapshot), 2)
            normal_eval = engine.analyze_events(normal_snapshot)
            self.assertEqual(normal_eval["severity"], "Normal")

            # Step 2: Generate harmless high-entropy .locked pattern in isolated sandbox
            original_paths = []
            locked_paths = []
            
            for i in range(15):
                original_path = os.path.join(
                    self.sandbox_dir, f"sim_victim_{i}.txt"
                )
                
                with open(original_path, "wb") as f:
                    f.write(os.urandom(2048))
                    
                original_paths.append(original_path)
                
            # Let the observer detect the original files
            time.sleep(0.5)
            
            # Perform actual file renames
            for original_path in original_paths:
                locked_path = os.path.splitext(original_path)[0] + ".locked"
                os.rename(original_path, locked_path)
                locked_paths.append(locked_path)

            # Wait up to 4s for observer events covering all 15 distinct .locked files
            deadline = time.time() + 4.0
            while time.time() < deadline:
                with cap_lock:

                    locked_seen = len({
                        os.path.normcase(
                            e.get("dest_path") or e.get("file_path", "")
                        )
                        for e in captured_events
                        if ".locked" in (
                            e.get("dest_path") or e.get("file_path", "")
                            ).lower()
                        })
                if locked_seen >= 15:
                    break
                time.sleep(0.1)

            with cap_lock:
                full_snapshot = list(captured_events)

            crit_eval = engine.analyze_events(
                full_snapshot,
                process_info={"pid": os.getpid(), "name": "python3", "cpu_percent": 82.0, "is_suspicious": True}
            )
            self.assertEqual(crit_eval["severity"], "Critical")
            self.assertEqual(crit_eval["threat_score"], 80)

            # Step 3: Verify quarantine copied evidence AND originals stayed intact
            q_files = os.listdir(self.quarantine_dir)
            self.assertGreaterEqual(len(q_files), 15)
            for lp in locked_paths:
                self.assertTrue(os.path.exists(lp), "Simulation mode must preserve originals")

            # Step 4: Verify SQLite persistence across fresh connection & API helpers
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) as cnt FROM file_events")
            ev_count = cur.fetchone()["cnt"]
            cur.execute("SELECT COUNT(*) as cnt FROM alerts WHERE severity = 'Critical'")
            al_count = cur.fetchone()["cnt"]
            cur.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 1")
            inc_row = cur.fetchone()
            conn.close()

            self.assertGreaterEqual(ev_count, 17)
            self.assertGreaterEqual(al_count, 1)
            self.assertIsNotNone(inc_row)
            self.assertEqual(inc_row["severity"], "Critical")

            history = api_main.get_real_threat_history()
            self.assertGreaterEqual(len(history), 1)
            self.assertEqual(history[-1]["score"], 80)

            # Step 5: Generate JSON, CSV, HTML reports from DB and verify accuracy
            reporter = ReportGenerator(output_dir=self.reports_dir)
            report_files = reporter.generate_all_reports_from_db()
            self.assertEqual(len(report_files), 3)
            json_path = next(p for p in report_files if p.endswith(".json"))
            csv_path = next(p for p in report_files if p.endswith(".csv"))
            with open(json_path, "r", encoding="utf-8") as jf:
                jdata = json.load(jf)
            self.assertEqual(jdata["incident"]["severity"], "Critical")
            self.assertEqual(jdata["incident"]["threat_score"], 80)
            with open(csv_path, "r", encoding="utf-8") as cf:
                self.assertIn("Critical", cf.read())

        finally:
            observer.stop()
            observer.join(timeout=3.0)
            if hasattr(observer, "is_alive"):
                self.assertFalse(observer.is_alive())


if __name__ == "__main__":
    unittest.main()
