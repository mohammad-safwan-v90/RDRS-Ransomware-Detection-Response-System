"""
Full End-to-End Integration Test for RDRS Pipeline using unittest with Temp Isolation
"""

import unittest
import os
import shutil
import tempfile
from datetime import datetime
from unittest.mock import patch
from rdrs.app.core.config import config
from rdrs.app.core.entropy import calculate_file_entropy
from rdrs.app.database.db import init_db
from rdrs.app.detectors.detection_engine import DetectionEngine
from rdrs.app.reports.report_generator import ReportGenerator


class TestFullIntegrationPipeline(unittest.TestCase):
    def test_full_pipeline(self):
        temp_dir = tempfile.mkdtemp(prefix="rdrs_test_integ_")
        sandbox_dir = os.path.join(temp_dir, "sandbox")
        quarantine_dir = os.path.join(temp_dir, "quarantine")
        reports_dir = os.path.join(temp_dir, "reports")
        temp_db_path = os.path.join(temp_dir, "integ.db")
        os.makedirs(sandbox_dir, exist_ok=True)
        os.makedirs(quarantine_dir, exist_ok=True)

        original_watch_paths = config._data["monitoring"]["watch_paths"]
        original_quarantine = config._data["quarantine"]["storage_dir"]
        config._data["monitoring"]["watch_paths"] = [sandbox_dir]
        config._data["quarantine"]["storage_dir"] = quarantine_dir

        with patch("rdrs.app.database.db.DB_PATH", temp_db_path):
            try:
                init_db()
                created_files = []
                now_str = datetime.now().isoformat()
                for i in range(5):
                    fp = os.path.join(sandbox_dir, f"file_{i}.txt")
                    with open(fp, "wb") as f:
                        f.write(os.urandom(1024))  # High entropy random bytes
                    created_files.append(fp)

                engine = DetectionEngine()
                events = [
                    {
                        "timestamp": now_str,
                        "event_type": "modified",
                        "file_path": fp,
                        "entropy": calculate_file_entropy(fp)
                    } for fp in created_files
                ]

                result = engine.analyze_events(events)
                self.assertEqual(result["high_entropy_count"], 5)

                quarantined = engine.quarantine_evidence(created_files)
                self.assertEqual(len(quarantined), 5)
                # Originals preserved in simulation mode
                for fp in created_files:
                    self.assertTrue(os.path.exists(fp))

                reporter = ReportGenerator(output_dir=reports_dir)
                incident_data = {
                    "incident_id": "INC-TEST-0001",
                    "timestamp": now_str,
                    "threat_score": result["threat_score"],
                    "severity": result["severity"],
                    "affected_files": created_files,
                    "detection_signals": result["detection_signals"]
                }
                json_path = reporter.generate_json_report(incident_data)
                html_path = reporter.generate_html_report(incident_data)
                csv_path = reporter.generate_csv_report([incident_data])
                self.assertTrue(os.path.exists(json_path))
                self.assertTrue(os.path.exists(html_path))
                self.assertTrue(os.path.exists(csv_path))

            finally:
                config._data["monitoring"]["watch_paths"] = original_watch_paths
                config._data["quarantine"]["storage_dir"] = original_quarantine
                shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
