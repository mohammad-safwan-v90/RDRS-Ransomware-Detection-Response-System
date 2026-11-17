"""
Comprehensive Isolated Unit & Real OS Tests for RDRS Watchdog Daemon,
Real File System Observer Events, Multi-Process Handshake Locking, DB Failure Resilience, and Health Reporting.
"""

import os
import sys
import json
import signal
import time
import shutil
import tempfile
import sqlite3
import subprocess
import unittest
from unittest.mock import patch
from datetime import datetime

sys.path.insert(0, os.path.abspath("."))

from rdrs.app.database.db import get_db_connection, init_db
from rdrs.app.detectors.file_monitor import RDRSFileEventHandler, Observer, BaseEventHandler
from rdrs.app.api.main import get_real_system_status, check_daemon_health
from rdrs_daemon import acquire_process_lock, release_process_lock, LOCK_FILE, STATUS_FILE


class IsolatedBaseTest(unittest.TestCase):
    """Base test class providing 100% data isolation from production DB and status files."""
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="rdrs_iso_env_")
        self.temp_db_path = os.path.join(self.temp_dir, "isolated_test.db")
        self.temp_status_path = os.path.join(self.temp_dir, "isolated_status.json")
        self.temp_lock_path = os.path.join(self.temp_dir, "isolated_daemon.lock")

        self.db_patch = patch("rdrs.app.database.db.DB_PATH", self.temp_db_path)
        self.status_patch = patch("rdrs_daemon.STATUS_FILE", self.temp_status_path)
        self.lock_patch = patch("rdrs_daemon.LOCK_FILE", self.temp_lock_path)

        self.db_patch.start()
        self.status_patch.start()
        self.lock_patch.start()

        init_db()

    def tearDown(self):
        patch.stopall()
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)


class TestObserverLifecycle(IsolatedBaseTest):
    def test_should_ignore_patterns(self):
        handler = BaseEventHandler(watch_dir=self.temp_dir)
        self.assertTrue(handler.should_ignore("data/sandbox/.git/config"))
        self.assertTrue(handler.should_ignore("data/sandbox/__pycache__/module.pyc"))
        self.assertTrue(handler.should_ignore("data/rdrs.db"))
        self.assertTrue(handler.should_ignore("data/rdrs.db-wal"))
        self.assertTrue(handler.should_ignore("data/monitor_status.json"))
        self.assertTrue(handler.should_ignore("data/rdrs_daemon.lock"))
        self.assertTrue(handler.should_ignore("data/sandbox/service.lock"))

        self.assertFalse(handler.should_ignore("data/sandbox/user_doc.txt"))
        self.assertFalse(handler.should_ignore("data/sandbox/subfolder/file.pdf"))
        self.assertFalse(handler.should_ignore("data/sandbox/victim_file.docx.locked"))

    def test_sqlite_persistence_on_file_events(self):
        handler = BaseEventHandler(watch_dir=self.temp_dir)
        test_file = os.path.join(self.temp_dir, "sample_document.txt")

        with open(test_file, "w") as f:
            f.write("Test content for RDRS file monitor persistence test.")

        handler.handle_event("created", test_file)

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM file_events WHERE file_path = ?", (test_file,))
        row = cur.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row["event_type"], "created")
        self.assertEqual(row["extension"], ".txt")
        self.assertGreater(row["entropy"], 0.0)

    def test_deleted_file_entropy_is_zero(self):
        handler = BaseEventHandler(watch_dir=self.temp_dir)
        deleted_file = os.path.join(self.temp_dir, "removed_file.docx")

        handler.handle_event("deleted", deleted_file)

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM file_events WHERE file_path = ? AND event_type = 'deleted'", (deleted_file,))
        row = cur.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row["entropy"], 0.0)

    def test_renamed_event_persistence(self):
        handler = BaseEventHandler(watch_dir=self.temp_dir)
        src_file = os.path.join(self.temp_dir, "original.docx")
        dest_file = os.path.join(self.temp_dir, "original.docx.locked")

        with open(dest_file, "wb") as f:
            f.write(os.urandom(128))

        handler.handle_event("renamed", src_file, dest_path=dest_file)

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM file_events WHERE dest_path = ?", (dest_file,))
        row = cur.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row["event_type"], "renamed")
        self.assertEqual(row["dest_path"], dest_file)


class TestRealObserverRuntime(IsolatedBaseTest):
    """Requirement 4: Test actual Watchdog Observer thread on real OS filesystem operations."""
    def _wait_for_db_event(self, event_type: str, file_path_substring: str, timeout: float = 4.0):
        start_t = time.time()
        while (time.time() - start_t) < timeout:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM file_events WHERE event_type = ? AND file_path LIKE ? ORDER BY id DESC LIMIT 1",
                (event_type, f"%{file_path_substring}%")
            )
            row = cur.fetchone()
            conn.close()
            if row:
                return dict(row)
            time.sleep(0.1)
        return None

    def test_real_observer_filesystem_events(self):

        watch_dir = tempfile.mkdtemp(
            prefix=".rdrs_observer_test_",
            dir=os.getcwd()
        )
        self.addCleanup(shutil.rmtree, watch_dir, ignore_errors=True)
        
        handler = RDRSFileEventHandler(watch_dir=watch_dir)
        observer = Observer()
        observer.schedule(handler, path=watch_dir, recursive=True)
        observer.start()
        
        try:
            self.assertTrue(observer.is_alive() if hasattr(observer, "is_alive") else True)

            # 1. Real File Creation
            test_file = os.path.join(watch_dir, "real_test_file.txt")
            with open(test_file, "w") as f:
                f.write("Initial contents of real filesystem event test file.")

            evt_created = self._wait_for_db_event("created", "real_test_file.txt")
            self.assertIsNotNone(evt_created, "Observer must detect real OS file creation and write to isolated SQLite DB")

            # 2. Real File Modification
            time.sleep(0.35)  # Avoid deduplication window
            with open(test_file, "a") as f:
                f.write("\nAppended modification text line.")

            evt_modified = self._wait_for_db_event("modified", "real_test_file.txt")
            self.assertIsNotNone(evt_modified, "Observer must detect real OS file modification and write to isolated SQLite DB")

            # 3. Real File Rename
            renamed_file = os.path.join(watch_dir, "real_test_file_renamed.txt")
            os.rename(test_file, renamed_file)

            evt_renamed = self._wait_for_db_event("renamed", "real_test_file")
            if not evt_renamed:
                evt_renamed = self._wait_for_db_event("created", "real_test_file_renamed.txt")
            self.assertIsNotNone(evt_renamed, "Observer must detect real OS file rename/move event")

            # 4. Real File Deletion
            os.remove(renamed_file)

            evt_deleted = self._wait_for_db_event("deleted", "real_test_file_renamed.txt")
            self.assertIsNotNone(evt_deleted, "Observer must detect real OS file deletion event")

        finally:
            observer.stop()
            observer.join(timeout=3.0)
            if hasattr(observer, "is_alive"):
                self.assertFalse(observer.is_alive(), "Observer thread must be stopped and inactive after join()")


class TestMultiProcessLock(IsolatedBaseTest):
    """Requirement 1: Test OS file locking across two distinct Python processes with explicit readiness handshake."""
    def test_multiprocess_file_lock(self):
        temp_lock = os.path.join(self.temp_dir, "mp_handshake_test_daemon.lock")
        script_path = os.path.join(self.temp_dir, "proc_a.py")

        with open(script_path, "w") as f:
            f.write(
                "import sys, time, os\n"
                "sys.path.insert(0, os.path.abspath('.'))\n"
                "from rdrs_daemon import acquire_process_lock, release_process_lock\n"
                "lock_path = sys.argv[1]\n"
                "if acquire_process_lock(lock_file_path=lock_path):\n"
                "    print('READY', flush=True)\n"
                "    time.sleep(3.0)\n"
                "    release_process_lock(lock_file_path=lock_path)\n"
                "    sys.exit(0)\n"
                "else:\n"
                "    print('FAILED', flush=True)\n"
                "    sys.exit(1)\n"
            )

        # Launch Process A in background
        proc_a = subprocess.Popen(
            [sys.executable, script_path, temp_lock],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        try:
            # Explicit readiness handshake: Wait until Process A confirms lock acquisition
            ready_signal = proc_a.stdout.readline().strip()
            self.assertEqual(ready_signal, "READY", "Process A must acquire lock first and send READY signal")

            # Process B (current test process) attempts lock acquisition while Process A holds it
            acquired_by_b = acquire_process_lock(lock_file_path=temp_lock)
            self.assertFalse(acquired_by_b, "Process B must be REJECTED while Process A holds the OS lock")

            # Wait for Process A to exit cleanly
            exit_code_a = proc_a.wait(timeout=6.0)
            self.assertEqual(exit_code_a, 0, "Process A should exit cleanly with code 0")

            # Process B attempts lock acquisition after Process A releases it
            acquired_after_release = acquire_process_lock(lock_file_path=temp_lock)
            self.assertTrue(acquired_after_release, "Process B must SUCCEED in acquiring lock after Process A releases it")

            release_process_lock(lock_file_path=temp_lock)
        finally:
            if proc_a.poll() is None:
                proc_a.kill()
            if proc_a.stdout:
                proc_a.stdout.close()
            if proc_a.stderr:
                proc_a.stderr.close()


class TestDatabaseFailureResilience(IsolatedBaseTest):
    """Requirement 6: Test handler resilience against forced database errors."""
    def test_database_failure_resilience(self):
        handler = BaseEventHandler(watch_dir=self.temp_dir)
        test_file = os.path.join(self.temp_dir, "db_error_doc.txt")
        with open(test_file, "w") as f:
            f.write("resilience test data")

        # 1. Force DB failure using mock side_effect
        with patch("rdrs.app.detectors.file_monitor.get_db_connection", side_effect=sqlite3.OperationalError("Database locked simulation")):
            try:
                handler.handle_event("created", test_file)
                error_handled_cleanly = True
            except Exception:
                error_handled_cleanly = False

        self.assertTrue(error_handled_cleanly, "File event handler must log error and NOT raise unhandled exception on DB failure")

        # 2. Verify subsequent event succeeds on restored DB connection
        test_file_2 = os.path.join(self.temp_dir, "db_recovered_doc.txt")
        with open(test_file_2, "w") as f:
            f.write("recovery test data")

        handler.handle_event("created", test_file_2)

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM file_events WHERE file_path = ?", (test_file_2,))
        row = cur.fetchone()
        conn.close()

        self.assertIsNotNone(row, "Event handler must recover and record subsequent events after a DB error")
        self.assertEqual(row["event_type"], "created")


class TestDaemonHealthStatus(IsolatedBaseTest):
    def test_daemon_health_check_stale_heartbeat(self):
        stale_status = {
            "is_monitoring": True,
            "observer_alive": True,
            "pid": os.getpid(),
            "last_heartbeat": "2020-01-01T00:00:00"
        }
        with open(self.temp_status_path, "w") as f:
            json.dump(stale_status, f)

        health = check_daemon_health(status_file_path=self.temp_status_path)
        self.assertFalse(health["is_monitoring"], "Stale heartbeat (>10s) must report is_monitoring = False")

    def test_daemon_health_check_dead_pid(self):
        dead_pid_status = {
            "is_monitoring": True,
            "observer_alive": True,
            "pid": 9999999,  # Non-existent PID
            "last_heartbeat": datetime.now().isoformat()
        }
        with open(self.temp_status_path, "w") as f:
            json.dump(dead_pid_status, f)

        health = check_daemon_health(status_file_path=self.temp_status_path)
        self.assertFalse(health["is_monitoring"], "Dead PID must report is_monitoring = False")

    def test_daemon_health_check_dead_observer_thread(self):
        dead_observer_status = {
            "is_monitoring": False,
            "observer_alive": False,
            "pid": os.getpid(),
            "last_heartbeat": datetime.now().isoformat()
        }
        with open(self.temp_status_path, "w") as f:
            json.dump(dead_observer_status, f)

        health = check_daemon_health(status_file_path=self.temp_status_path)
        self.assertFalse(health["is_monitoring"], "Terminated observer thread must report is_monitoring = False")


class TestDaemonErrorStatus(IsolatedBaseTest):
    def test_daemon_error_status_format(self):
        error_status = {
            "is_monitoring": False,
            "observer_alive": False,
            "pid": None,
            "started_at": datetime.now().isoformat(),
            "last_heartbeat": datetime.now().isoformat(),
            "watched_path": self.temp_dir,
            "last_event_at": None,
            "last_error": "Daemon spawn failed (python3): ENOENT",
            "backend_engine": "Unavailable"
        }
        with open(self.temp_status_path, "w") as f:
            json.dump(error_status, f)

        health = check_daemon_health(status_file_path=self.temp_status_path)
        self.assertFalse(health["is_monitoring"], "Failed daemon spawn status must report is_monitoring = False")
        self.assertIn("Monitoring marked false", health.get("reason", ""), "reason must report false/dead observer status")


class TestMonitoredDirectoryFailures(IsolatedBaseTest):
    def test_verify_watch_directory_missing_and_non_directory(self):
        from rdrs_daemon import verify_watch_directory

        missing_dir = os.path.join(self.temp_dir, "does_not_exist")
        with self.assertRaises(FileNotFoundError):
            verify_watch_directory(missing_dir)

        regular_file = os.path.join(self.temp_dir, "not_a_dir.txt")
        with open(regular_file, "w", encoding="utf-8") as f:
            f.write("file")
        with self.assertRaises(FileNotFoundError):
            verify_watch_directory(regular_file)

        valid_dir = os.path.join(self.temp_dir, "valid_dir")
        os.makedirs(valid_dir, exist_ok=True)
        verify_watch_directory(valid_dir)

    def test_fallback_observer_reports_deleted_directory_error(self):
        from rdrs.app.detectors.file_monitor import FallbackObserver

        watch_dir = os.path.join(self.temp_dir, "fallback_watch")
        os.makedirs(watch_dir, exist_ok=True)
        handler = BaseEventHandler(watch_dir=watch_dir)
        obs = FallbackObserver()
        obs.schedule(handler, watch_dir, recursive=True)
        obs.start()
        try:
            self.assertTrue(obs.is_alive())
            shutil.rmtree(watch_dir)
            deadline = time.time() + 3.0
            while time.time() < deadline and obs.is_alive():
                time.sleep(0.1)
            self.assertFalse(obs.is_alive(), "FallbackObserver must stop when monitored directory is deleted")
            self.assertIsNotNone(obs.last_error)
        finally:
            obs.stop()
            obs.join(timeout=2.0)

    def test_isolated_daemon_startup_duplicate_prevention_and_shutdown(self):
        iso_sandbox = os.path.join(self.temp_dir, "iso_sandbox")
        os.makedirs(iso_sandbox, exist_ok=True)
        runtime_pid_path = os.path.join(self.temp_dir, "daemon_runtime.pid")
        runner_code = (
            "import os, sys\n"
            "sys.path.insert(0, os.path.abspath('.'))\n"
            "import rdrs_daemon\n"
            "from rdrs.app.core.config import config\n"
            f"rdrs_daemon.LOCK_FILE = {self.temp_lock_path!r}\n"
            f"rdrs_daemon.STATUS_FILE = {self.temp_status_path!r}\n"
            f"config._data['monitoring']['watch_paths'] = [{iso_sandbox!r}]\n"
            f"import rdrs.app.database.db as db_mod\n"
            f"db_mod.DB_PATH = {self.temp_db_path!r}\n"
            f"with open({runtime_pid_path!r}, 'w', encoding='utf-8') as pf:\n"
"    pf.write(str(os.getpid()))\n"
"    pf.flush()\n"
"rdrs_daemon.main()\n"
        )
        script_path = os.path.join(self.temp_dir, "run_iso_daemon.py")
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(runner_code)

        env = os.environ.copy()
        env["PYTHONPATH"] = os.path.abspath(".")
        proc1 = subprocess.Popen(
            [sys.executable, script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        )
        proc2 = None
        try:
            deadline = time.time() + 6.0
            ready = False

            while time.time() < deadline:
                if os.path.exists(self.temp_status_path) and os.path.exists(runtime_pid_path):
                    try:
                        with open(self.temp_status_path, "r", encoding="utf-8") as sf:
                            st = json.load(sf)

                        with open(runtime_pid_path, "r", encoding="utf-8") as pf:
                            expected_pid = int(pf.read().strip())

                        if st.get("is_monitoring") and st.get("pid") == expected_pid:
                            ready = True
                            break

                    except Exception:
                        pass

                time.sleep(0.1)
            self.assertTrue(ready, "Daemon must start and publish healthy monitor_status.json")

            # Duplicate daemon launch must exit cleanly with code 0 without overwriting PID
            proc2 = subprocess.Popen(
                [sys.executable, script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env
            )
            dup_code = proc2.wait(timeout=6.0)
            self.assertEqual(dup_code, 0, "Duplicate daemon must exit cleanly with status 0")

            # Graceful SIGTERM shutdown
            proc1.send_signal(signal.CTRL_BREAK_EVENT)
            exit_code = proc1.wait(timeout=8.0)
            self.assertEqual(exit_code, 0, "Daemon must exit cleanly on SIGTERM")

            with open(self.temp_status_path, "r", encoding="utf-8") as sf:
                final_status = json.load(sf)
            self.assertFalse(final_status["is_monitoring"])
            self.assertIsNone(final_status["pid"])
        finally:
            for p in (proc2, proc1):
                if p is not None and p.poll() is None:
                    p.kill()
                    p.wait(timeout=3.0)
                if p is not None:
                    if p.stdout:
                        p.stdout.close()
                    if p.stderr:
                        p.stderr.close()


if __name__ == "__main__":
    unittest.main()

