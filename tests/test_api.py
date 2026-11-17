"""
API & Reporting Functionality Unit Tests using unittest with Isolated Temporary Storage
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta
from rdrs.app.core.config import config
from rdrs.app.database.db import init_db, get_db_connection
import rdrs.app.api.main as api_main
from rdrs.app.reports.report_generator import ReportGenerator


class TestAPIFunctions(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="rdrs_test_api_iso_")
        self.temp_db_path = os.path.join(self.temp_dir, "isolated_api.db")
        self.temp_sandbox = os.path.join(self.temp_dir, "sandbox")
        self.temp_quarantine = os.path.join(self.temp_dir, "quarantine")
        self.temp_reports = os.path.join(self.temp_dir, "reports")
        self.temp_status = os.path.join(self.temp_dir, "status.json")
        os.makedirs(self.temp_sandbox, exist_ok=True)
        os.makedirs(self.temp_quarantine, exist_ok=True)
        os.makedirs(self.temp_reports, exist_ok=True)

        self.orig_watch_paths = config._data["monitoring"]["watch_paths"]
        self.orig_quarantine_dir = api_main.detection_engine.quarantine_dir
        self.orig_reports_dir = api_main.report_generator.output_dir

        config._data["monitoring"]["watch_paths"] = [self.temp_sandbox]
        api_main.detection_engine.quarantine_dir = self.temp_quarantine
        api_main.report_generator.output_dir = self.temp_reports

        self.db_patcher = patch("rdrs.app.database.db.DB_PATH", self.temp_db_path)
        self.db_patcher.start()
        init_db()

    def tearDown(self):
        self.db_patcher.stop()
        config._data["monitoring"]["watch_paths"] = self.orig_watch_paths
        api_main.detection_engine.quarantine_dir = self.orig_quarantine_dir
        api_main.report_generator.output_dir = self.orig_reports_dir
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_status_response(self):
        status = api_main.get_real_system_status()
        self.assertIn("threat_score", status)
        self.assertIn("threat_level", status)
        self.assertIn("cpu_usage", status)

    def test_health_response_degraded_and_healthy(self):
        degraded = api_main.get_real_health(status_file_path=self.temp_status)
        self.assertEqual(degraded["status"], "degraded")
        self.assertFalse(degraded["daemon_monitoring"])
        self.assertTrue(degraded["database_accessible"])

        with open(self.temp_status, "w", encoding="utf-8") as f:
            json.dump({
                "is_monitoring": True,
                "observer_alive": True,
                "pid": os.getpid(),
                "last_heartbeat": datetime.now().isoformat()
            }, f)

        healthy = api_main.get_real_health(status_file_path=self.temp_status)
        self.assertEqual(healthy["status"], "healthy")
        self.assertTrue(healthy["daemon_monitoring"])
        self.assertEqual(healthy["daemon_pid"], os.getpid())

    def test_simulation_execution_isolated(self):
        res = api_main.run_sandbox_simulation("entropy_spike")
        self.assertEqual(res["status"], "success")
        self.assertIn("Threat Score", res["message"])
        # Verify high-entropy files were written to the sandbox and reports
        self.assertTrue(any(f.endswith(".locked") for f in os.listdir(self.temp_sandbox)))
        self.assertEqual(len(os.listdir(self.temp_quarantine)), 0)
        self.assertGreater(len(os.listdir(self.temp_reports)), 0)
    def test_full_simulation_quarantines_evidence(self):
        res = api_main.run_sandbox_simulation("full_simulation")

        self.assertEqual(res["status"], "success")
        self.assertIn("Threat Score", res["message"])
        self.assertGreater(len(os.listdir(self.temp_quarantine)), 0)
        self.assertGreater(len(os.listdir(self.temp_reports)), 0)
    def test_threat_history_empty_state(self):
        history = api_main.get_real_threat_history()
        self.assertEqual(history, [])

    def test_threat_history_24h_filter_and_order(self):
        now = datetime.now()
        old_ts = (now - timedelta(hours=30)).isoformat()
        ts_1 = (now - timedelta(hours=2)).isoformat()
        ts_2 = (now - timedelta(hours=1)).isoformat()

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO alerts (timestamp, severity, threat_score, message, detection_signals, affected_files) VALUES (?, ?, ?, ?, ?, ?)",
            (old_ts, "Warning", 45, "Old alert", "[]", "[]")
        )
        cur.execute(
            "INSERT INTO alerts (timestamp, severity, threat_score, message, detection_signals, affected_files) VALUES (?, ?, ?, ?, ?, ?)",
            (ts_1, "Warning", 55, "Recent alert 1", "[]", "[]")
        )
        cur.execute(
            "INSERT INTO alerts (timestamp, severity, threat_score, message, detection_signals, affected_files) VALUES (?, ?, ?, ?, ?, ?)",
            (ts_2, "Critical", 85, "Recent alert 2", "[]", "[]")
        )
        conn.commit()
        conn.close()

        history = api_main.get_real_threat_history()
        self.assertEqual(len(history), 2)
        self.assertEqual([h["score"] for h in history], [55, 85])
        self.assertEqual(history[0]["full_timestamp"], ts_1)
        self.assertEqual(history[1]["full_timestamp"], ts_2)

    def test_html_report_xss_escaping(self):
        reporter = ReportGenerator(output_dir=self.temp_reports)
        malicious_payload = {
            "incident_id": "INC-<script>alert(1)</script>",
            "timestamp": "<img src=x onerror=alert(1)>",
            "severity": "Critical",
            "threat_score": 95,
            "detection_signals": ["<script>evil()</script>"],
            "affected_files": ["/sandbox/<svg onload=alert(1)>.locked"]
        }
        report_path = reporter.generate_html_report(malicious_payload)
        self.assertTrue(os.path.exists(report_path))
        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertNotIn("<script>alert(1)</script>", content)
        self.assertNotIn("<script>evil()</script>", content)
        self.assertNotIn("<svg onload=alert(1)>", content)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", content)

    def test_reports_empty_db_and_invalid_input_handling(self):
        reporter = ReportGenerator(output_dir=self.temp_reports)
        # Empty DB should only produce header-only CSV
        files = reporter.generate_all_reports_from_db()
        self.assertEqual(len(files), 1)
        self.assertTrue(files[0].endswith(".csv"))
        with open(files[0], "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("incident_id,timestamp,threat_score,severity"))

        # Invalid inputs raise ValueError instead of crashing unpredictably
        with self.assertRaises(ValueError):
            reporter.generate_json_report(None)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            reporter.generate_html_report("bad")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            reporter.generate_csv_report("not_a_list")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            reporter.generate_csv_report([None])  # type: ignore[list-item]

        # Valid JSON and CSV verify field integrity
        sample = {
            "incident_id": "INC-20261113-0042",
            "timestamp": "2026-11-13T12:00:00",
            "threat_score": 95,
            "severity": "Critical",
            "affected_files_count": 2,
            "affected_files": ["a.locked", "b.locked"],
            "process_name": "sim.exe",
            "process_pid": 4321,
            "status": "Contained (Simulation)",
            "detection_signals": ["Rapid encryption-like activity"]
        }
        jp = reporter.generate_json_report(sample)
        cp = reporter.generate_csv_report([sample])
        with open(jp, "r", encoding="utf-8") as jf:
            jdata = json.load(jf)
        self.assertEqual(jdata["incident"]["incident_id"], "INC-20261113-0042")
        self.assertEqual(jdata["incident"]["threat_score"], 95)
        with open(cp, "r", encoding="utf-8") as cf:
            csv_body = cf.read()
        self.assertIn("INC-20261113-0042", csv_body)
        self.assertIn("Critical", csv_body)

    def test_health_response_database_failure(self):
        with open(self.temp_status, "w", encoding="utf-8") as f:
            json.dump({
                "is_monitoring": True,
                "observer_alive": True,
                "pid": os.getpid(),
                "last_heartbeat": datetime.now().isoformat()
            }, f)
        with patch("rdrs.app.api.main.get_db_connection", side_effect=RuntimeError("DB offline")):
            res = api_main.get_real_health(status_file_path=self.temp_status)
        self.assertEqual(res["status"], "degraded")
        self.assertFalse(res["database_accessible"])
        self.assertIn("DB offline", res["database_error"])

    def test_windows_health_check_never_calls_os_kill(self):
        with open(self.temp_status, "w", encoding="utf-8") as f:
            json.dump({
                "is_monitoring": True,
                "observer_alive": True,
                "pid": 24820,
                "last_heartbeat": datetime.now().isoformat()
            }, f)

        fake_psutil = type("FakePsutil", (), {
            "STATUS_ZOMBIE": "zombie",
            "NoSuchProcess": type("NoSuchProcess", (Exception,), {}),
            "AccessDenied": type("AccessDenied", (Exception,), {}),
            "pid_exists": staticmethod(lambda pid: pid == 24820),
            "Process": staticmethod(lambda pid: type("P", (), {
                "is_running": staticmethod(lambda: True),
                "status": staticmethod(lambda: "running")
            })())
        })()

        with patch("rdrs.app.api.main.sys.platform", "win32"), \
             patch("rdrs.app.api.main.os.kill", side_effect=AssertionError("os.kill must not be called on Windows")), \
             patch.dict("sys.modules", {"psutil": fake_psutil}):
            res_alive = api_main.check_daemon_health(status_file_path=self.temp_status)
            self.assertTrue(res_alive["is_monitoring"])
            self.assertEqual(res_alive["pid"], 24820)

            with open(self.temp_status, "w", encoding="utf-8") as f:
                json.dump({
                    "is_monitoring": True,
                    "observer_alive": True,
                    "pid": 999999,
                    "last_heartbeat": datetime.now().isoformat()
                }, f)
            res_dead = api_main.check_daemon_health(status_file_path=self.temp_status)
            self.assertFalse(res_dead["is_monitoring"])
            self.assertEqual(res_dead["reason"], "Process dead")

        self.assertFalse(api_main._is_process_alive(0))
        self.assertFalse(api_main._is_process_alive(-1))
        self.assertFalse(api_main._is_process_alive(True))

    def test_windows_ctypes_fallback_never_calls_os_kill(self):
        import ctypes
        import types

        class FakeKernel32:
            def __init__(self, active=True, handle=101, last_err=0):
                self.active = active
                self.handle = handle
                self.last_err = last_err
                self.closed = []

            def OpenProcess(self, access, inherit, pid):
                return self.handle

            def GetLastError(self):
                return self.last_err

            def GetExitCodeProcess(self, handle, exit_code_ptr):
                # 259 = STILL_ACTIVE
                val = 259 if self.active else 0
                ctypes.cast(exit_code_ptr, ctypes.POINTER(ctypes.c_ulong))[0] = val
                return 1

            def CloseHandle(self, handle):
                self.closed.append(handle)
                return 1

        fake_windll = types.SimpleNamespace(kernel32=FakeKernel32(active=True, handle=101))
        with patch("rdrs.app.api.main.sys.platform", "win32"), \
             patch("rdrs.app.api.main.os.kill", side_effect=AssertionError("os.kill must not be called on Windows")), \
             patch.dict("sys.modules", {"psutil": None}), \
             patch.object(ctypes, "windll", fake_windll, create=True):
            self.assertTrue(api_main._is_process_alive(24820))
            self.assertEqual(fake_windll.kernel32.closed, [101])

            fake_windll.kernel32 = FakeKernel32(active=False, handle=102)
            self.assertFalse(api_main._is_process_alive(24820))
            self.assertEqual(fake_windll.kernel32.closed, [102])

            fake_windll.kernel32 = FakeKernel32(active=False, handle=0, last_err=5)
            self.assertTrue(api_main._is_process_alive(24820))

            fake_windll.kernel32 = FakeKernel32(active=False, handle=0, last_err=87)
            self.assertFalse(api_main._is_process_alive(24820))

    def test_missing_and_corrupt_config_reporting(self):
        from rdrs.app.core.config import RDRSConfig

        missing_cfg = RDRSConfig(config_path=os.path.join(self.temp_dir, "missing_config.yaml"))
        self.assertFalse(missing_cfg.config_loaded)
        self.assertIsNotNone(missing_cfg.config_error)
        self.assertIn("not found", missing_cfg.config_error)
        self.assertTrue(missing_cfg.simulation_mode)
        self.assertEqual(missing_cfg.watch_paths, ["./data/sandbox"])

        bad_cfg_path = os.path.join(self.temp_dir, "bad_config.yaml")
        with open(bad_cfg_path, "w", encoding="utf-8") as f:
            f.write(":\n  - [unclosed yaml bracket\n")
        bad_cfg = RDRSConfig(config_path=bad_cfg_path)
        self.assertFalse(bad_cfg.config_loaded)
        self.assertIsNotNone(bad_cfg.config_error)
        self.assertEqual(bad_cfg.entropy_threshold, 7.2)

    def test_health_check_rejects_missing_pid_and_bad_heartbeat(self):
        with open(self.temp_status, "w", encoding="utf-8") as f:
            json.dump({
                "is_monitoring": True,
                "observer_alive": True,
                "pid": None,
                "last_heartbeat": datetime.now().isoformat()
            }, f)
        res_no_pid = api_main.check_daemon_health(status_file_path=self.temp_status)
        self.assertFalse(res_no_pid["is_monitoring"])
        self.assertEqual(res_no_pid["reason"], "Missing daemon PID")

        with open(self.temp_status, "w", encoding="utf-8") as f:
            json.dump({
                "is_monitoring": True,
                "observer_alive": True,
                "pid": os.getpid(),
                "last_heartbeat": "not-a-timestamp"
            }, f)
        res_bad_hb = api_main.check_daemon_health(status_file_path=self.temp_status)
        self.assertFalse(res_bad_hb["is_monitoring"])
        self.assertEqual(res_bad_hb["reason"], "Invalid heartbeat timestamp")

        with open(self.temp_status, "w", encoding="utf-8") as f:
            json.dump({
                "is_monitoring": True,
                "observer_alive": True,
                "pid": os.getpid()
            }, f)
        res_missing_hb = api_main.check_daemon_health(status_file_path=self.temp_status)
        self.assertFalse(res_missing_hb["is_monitoring"])
        self.assertEqual(res_missing_hb["reason"], "Missing heartbeat")

    def test_update_nonexistent_records_return_not_found(self):
        alert_res = api_main.update_alert_status(999999, "Resolved")
        self.assertEqual(alert_res.get("status_code"), 404)
        self.assertIn("not found", alert_res.get("error", "").lower())

        inc_res = api_main.update_incident_status("INC-DOES-NOT-EXIST", "Resolved")
        self.assertEqual(inc_res.get("status_code"), 404)
        self.assertIn("not found", inc_res.get("error", "").lower())

    def test_repeated_health_and_status_requests_on_windows_mock(self):
        with open(self.temp_status, "w", encoding="utf-8") as f:
            json.dump({
                "is_monitoring": True,
                "observer_alive": True,
                "pid": os.getpid(),
                "last_heartbeat": datetime.now().isoformat()
            }, f)

        fake_psutil = type("FakePsutil", (), {
            "STATUS_ZOMBIE": "zombie",
            "NoSuchProcess": type("NoSuchProcess", (Exception,), {}),
            "AccessDenied": type("AccessDenied", (Exception,), {}),
            "cpu_percent": staticmethod(lambda interval=0.05: 12.5),
            "pid_exists": staticmethod(lambda pid: pid == os.getpid()),
            "Process": staticmethod(lambda pid: type("P", (), {
                "is_running": staticmethod(lambda: True),
                "status": staticmethod(lambda: "running")
            })())
        })()

        with patch("rdrs.app.api.main.sys.platform", "win32"), \
             patch("rdrs.app.api.main.os.kill", side_effect=AssertionError("os.kill must not be called on Windows")), \
             patch.dict("sys.modules", {"psutil": fake_psutil}):
            for _ in range(5):
                health = api_main.get_real_health(status_file_path=self.temp_status)
                status = api_main.get_real_system_status()
                self.assertEqual(health["status"], "healthy")
                self.assertTrue(health["daemon_monitoring"])
                self.assertIn("threat_score", status)
                self.assertEqual(status["cpu_usage"], 12.5)


if __name__ == '__main__':
    unittest.main()

