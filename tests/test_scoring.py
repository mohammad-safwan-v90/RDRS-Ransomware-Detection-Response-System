"""
Threat Scoring Matrix & Boundary Unit Tests using unittest with Isolated Temp Storage
"""

import os
import shutil
import tempfile
import unittest
from datetime import datetime
from unittest.mock import patch
from rdrs.app.core.config import config
from rdrs.app.database.db import init_db
from rdrs.app.detectors.detection_engine import DetectionEngine


class TestScoringMatrix(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="rdrs_test_score_")
        self.temp_db_path = os.path.join(self.temp_dir, "score.db")
        self.temp_quarantine = os.path.join(self.temp_dir, "quarantine")
        os.makedirs(self.temp_quarantine, exist_ok=True)
        self.orig_quarantine_dir = config._data["quarantine"]["storage_dir"]
        config._data["quarantine"]["storage_dir"] = self.temp_quarantine
        self.db_patcher = patch("rdrs.app.database.db.DB_PATH", self.temp_db_path)
        self.db_patcher.start()
        init_db()

    def tearDown(self):
        self.db_patcher.stop()
        config._data["quarantine"]["storage_dir"] = self.orig_quarantine_dir
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_individual_signals_and_weights(self):
        engine = DetectionEngine()
        now = datetime.now().isoformat()

        # 1. Rapid encryption alone (40) -> exact Warning lower bound
        rapid_events = [
            {"timestamp": now, "event_type": "modified", "file_path": f"plain_{i}.txt", "entropy": 3.5}
            for i in range(15)
        ]
        res_rapid = engine.analyze_events(rapid_events)
        self.assertEqual(res_rapid["threat_score"], 40)
        self.assertEqual(res_rapid["severity"], "Warning")

        # 2. Mass rename alone (30) -> Normal
        rename_events = [
            {"timestamp": now, "event_type": "renamed", "file_path": f"file_{i}.dat", "entropy": 4.0}
            for i in range(8)
        ]
        res_rename = engine.analyze_events(rename_events)
        self.assertEqual(res_rename["threat_score"], 30)
        self.assertEqual(res_rename["severity"], "Normal")

        # 3. High entropy alone (25) -> Normal (false-positive protection)
        entropy_events = [
            {"timestamp": now, "event_type": "created", "file_path": "compressed.zip", "entropy": 7.9}
        ]
        res_ent = engine.analyze_events(entropy_events)
        self.assertEqual(res_ent["threat_score"], 25)
        self.assertEqual(res_ent["severity"], "Normal")

        # 4. CPU spike alone (15) -> Normal
        res_cpu = engine.analyze_events([], process_info={"pid": 100, "name": "worker.exe", "cpu_percent": 85.0, "is_suspicious": False})
        self.assertEqual(res_cpu["threat_score"], 15)
        self.assertEqual(res_cpu["severity"], "Normal")

        # 5. Unknown program alone (10) -> Normal
        res_unk = engine.analyze_events([], process_info={"pid": 101, "name": "odd.exe", "cpu_percent": 5.0, "is_suspicious": True})
        self.assertEqual(res_unk["threat_score"], 10)
        self.assertEqual(res_unk["severity"], "Normal")

    def test_boundary_classification_and_combined_signals(self):
        engine = DetectionEngine()
        now = datetime.now().isoformat()

        # Score 35 (< 40) -> Normal: high_entropy (25) + unknown_program (10)
        res_35 = engine.analyze_events(
            [{"timestamp": now, "event_type": "created", "file_path": "iso.bin", "entropy": 7.8}],
            process_info={"pid": 200, "name": "unknown.exe", "cpu_percent": 10.0, "is_suspicious": True}
        )
        self.assertEqual(res_35["threat_score"], 35)
        self.assertEqual(res_35["severity"], "Normal")

        # Score 40 (>= 40 and < 70) -> Warning: high_entropy (25) + cpu_spike (15)
        res_40 = engine.analyze_events(
            [{"timestamp": now, "event_type": "created", "file_path": "iso.bin", "entropy": 7.8}],
            process_info={"pid": 201, "name": "encoder.exe", "cpu_percent": 80.0, "is_suspicious": False}
        )
        self.assertEqual(res_40["threat_score"], 40)
        self.assertEqual(res_40["severity"], "Warning")

        # Score 65 (< 70) -> Warning: rapid_mods (40) + high_entropy (25)
        events_65 = [
            {"timestamp": now, "event_type": "modified", "file_path": f"doc_{i}.dat", "entropy": 7.8}
            for i in range(15)
        ]
        res_65 = engine.analyze_events(events_65)
        self.assertEqual(res_65["threat_score"], 65)
        self.assertEqual(res_65["severity"], "Warning")

        # Score 70 (>= 70) -> Critical upper-band transition: rapid_mods (40) + mass_rename (30)
        events_70 = [
            {"timestamp": now, "event_type": "modified", "file_path": f"doc_{i}.txt", "entropy": 3.5}
            for i in range(15)
        ] + [
            {"timestamp": now, "event_type": "renamed", "file_path": f"ren_{i}.txt", "entropy": 3.5}
            for i in range(8)
        ]
        res_70 = engine.analyze_events(events_70)
        self.assertEqual(res_70["threat_score"], 70)
        self.assertEqual(res_70["severity"], "Critical")

    def test_duplicate_events_do_not_inflate_score(self):
        engine = DetectionEngine()
        now = datetime.now().isoformat()
        identical_evt = {"timestamp": now, "event_type": "modified", "file_path": "same_file.txt", "entropy": 7.9}
        # 20 identical duplicate event dicts should count once
        res = engine.analyze_events([identical_evt.copy() for _ in range(20)])
        self.assertEqual(res["recent_events_count"], 1)
        self.assertEqual(res["modifications_count"], 1)
        self.assertEqual(res["threat_score"], 25)
        self.assertEqual(res["severity"], "Normal")


    
    def test_new_file_created_then_modified_is_not_rapid_encryption(self):
        engine = DetectionEngine()
        now = datetime.now().isoformat()

        events = []

        for i in range(15):
            path = f"new_document_{i}.txt"

            events.append({
                "timestamp": now,
                "event_type": "created",
                "file_path": path,
                "entropy": 3.5
            })

            events.append({
                "timestamp": now,
                "event_type": "modified",
                "file_path": path,
                "entropy": 3.5
            })

        result = engine.analyze_events(events)

        self.assertEqual(result["modifications_count"], 0)
        self.assertEqual(result["threat_score"], 0)
        self.assertEqual(result["severity"], "Normal")



    def test_score_capping_at_100(self):
        engine = DetectionEngine()
        now = datetime.now().isoformat()
        events = [
            {"timestamp": now, "event_type": "modified", "file_path": f"f_{i}.locked", "entropy": 7.95}
            for i in range(20)
        ] + [
            {"timestamp": now, "event_type": "renamed", "file_path": f"f_{i}.txt -> f_{i}.locked", "entropy": 7.95}
            for i in range(10)
        ]
        process_info = {"pid": 9999, "name": "unknown_proc.exe", "cpu_percent": 90.0, "is_suspicious": True}

        result = engine.analyze_events(events, process_info)
        self.assertEqual(result["threat_score"], 100)
        self.assertEqual(result["severity"], "Critical")


if __name__ == '__main__':
    unittest.main()
