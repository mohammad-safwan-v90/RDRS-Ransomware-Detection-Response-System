"""
RDRS Standalone Watchdog Daemon Process
Manages single Watchdog Observer instance, cross-process OS file locking,
observer thread health monitoring, and real-time SQLite file event persistence.
"""

import os
import sys
import json
import time
import signal
import threading
from collections import deque
from datetime import datetime, timedelta

sys.path.insert(0, os.path.abspath("."))

from rdrs.app.core.config import config
from rdrs.app.database.db import init_db
from rdrs.app.detectors.file_monitor import RDRSFileEventHandler, Observer, HAS_WATCHDOG
from rdrs.app.detectors.detection_engine import DetectionEngine
from rdrs.app.reports.report_generator import ReportGenerator
from rdrs.app.core.logging_config import logger

LOCK_FILE = os.path.abspath("data/rdrs_daemon.lock")
STATUS_FILE = os.path.abspath("data/monitor_status.json")
SANDBOX_DIR = os.path.abspath("data/sandbox")

lock_fd = None
running = True
last_event_timestamp = None
last_error_message = None
session_started_at = None

_is_locked_in_process = False
_event_window = deque()
_window_lock = threading.Lock()
_last_alert_ts = 0.0
_last_alert_severity = "Normal"
_detection_engine = None
_report_generator = None


def _get_engine():
    global _detection_engine, _report_generator
    if _detection_engine is None:
        _detection_engine = DetectionEngine()
    if _report_generator is None:
        _report_generator = ReportGenerator()
    return _detection_engine, _report_generator


def acquire_process_lock(lock_file_path: str = None):
    global lock_fd, _is_locked_in_process
    if _is_locked_in_process:
        logger.warning("[Daemon] Another instance is already running in this process.")
        return False

    target_path = os.path.abspath(lock_file_path or LOCK_FILE)
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    raw_fd = None
    fd = None
    try:
        raw_fd = os.open(target_path, os.O_RDWR | os.O_CREAT, 0o666)
        fd = os.fdopen(raw_fd, "r+")
        raw_fd = None

        fd.seek(0)
        if sys.platform.startswith("win"):
            import msvcrt
            msvcrt.locking(fd.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

        fd.seek(0)
        fd.truncate(0)
        fd.write(str(os.getpid()))
        fd.flush()

        lock_fd = fd
        _is_locked_in_process = True
        return True
    except (IOError, OSError):
        logger.warning(f"[Daemon] Another instance is already running (locked {target_path}). Exiting.")
        if raw_fd is not None:
            try:
                os.close(raw_fd)
            except Exception:
                pass
        if fd is not None:
            try:
                fd.close()
            except Exception:
                pass
        return False


def release_process_lock(lock_file_path: str = None):
    global lock_fd, _is_locked_in_process
    if lock_fd:
        try:
            lock_fd.seek(0)
            if sys.platform.startswith("win"):
                import msvcrt
                msvcrt.locking(lock_fd.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            lock_fd.close()
        except Exception:
            pass
        lock_fd = None
    _is_locked_in_process = False



def update_status_file(is_monitoring: bool, pid: int = None, observer_alive: bool = True, error: str = None):
    os.makedirs(os.path.dirname(STATUS_FILE), exist_ok=True)
    status_data = {
        "is_monitoring": is_monitoring and observer_alive,
        "observer_alive": observer_alive,
        "pid": pid if (is_monitoring and observer_alive) else None,
        "started_at": session_started_at or datetime.now().isoformat(),
        "last_heartbeat": datetime.now().isoformat(),
        "watched_path": SANDBOX_DIR,
        "last_event_at": last_event_timestamp,
        "last_error": error or last_error_message,
        "backend_engine": "Watchdog" if HAS_WATCHDOG else "Fallback Poller"
    }
    try:
        tmp_file = STATUS_FILE + ".tmp"
        with open(tmp_file, "w") as f:
            json.dump(status_data, f, indent=2)
        os.replace(tmp_file, STATUS_FILE)
    except Exception as ex:
        logger.error(f"[Daemon] Failed writing status file: {ex}")


def event_callback(event_data: dict):
    global last_event_timestamp, _last_alert_ts, _last_alert_severity
    last_event_timestamp = datetime.now().isoformat()
    logger.info(f"[Daemon Event] {event_data.get('event_type')}: {event_data.get('file_path')}")

    with _window_lock:
        now = datetime.now()
        cutoff = now - timedelta(seconds=config.time_window_seconds)
        _event_window.append(event_data)
        while _event_window:
            try:
                evt_dt = datetime.fromisoformat(_event_window[0]["timestamp"])
                if evt_dt < cutoff:
                    _event_window.popleft()
                else:
                    break
            except Exception:
                break

        window_snapshot = list(_event_window)

    now_epoch = time.time()
    engine, reporter = _get_engine()
    in_cooldown = (now_epoch - _last_alert_ts) < 5.0
    if in_cooldown and _last_alert_severity == "Critical":
        return

    mod_cnt = sum(1 for e in window_snapshot if e.get("event_type") in ("modified", "created"))
    ren_cnt = sum(
        1 for e in window_snapshot
        if e.get("event_type") == "renamed"
    )

    rapid_thresh = config.get("detection", {}).get("rapid_mods_threshold", 15)
    rename_thresh = config.get("detection", {}).get("mass_rename_threshold", 8)

    if in_cooldown and _last_alert_severity == "Warning" and not (mod_cnt >= rapid_thresh and ren_cnt >= rename_thresh):
        return

    if (mod_cnt >= rapid_thresh) or (ren_cnt >= rename_thresh):
        result = engine.analyze_events(window_snapshot)
        if result["severity"] in ("Warning", "Critical"):
            _last_alert_ts = now_epoch
            _last_alert_severity = result["severity"]
            logger.warning(f"[Daemon Detection] {result['severity']} threat detected (Score: {result['threat_score']}/100)")
            if result["severity"] == "Critical":
                with _window_lock:
                    _event_window.clear()
                reporter.generate_all_reports_from_db()


def signal_handler(signum, frame):
    global running
    logger.info(f"[Daemon] Received signal {signum}, initiating graceful shutdown...")
    running = False


def verify_watch_directory(watch_dir: str) -> None:
    if not watch_dir or not os.path.isdir(watch_dir):
        raise FileNotFoundError(f"Monitored directory does not exist: {watch_dir}")
    if not os.access(watch_dir, os.R_OK):
        raise PermissionError(f"Monitored directory is not readable: {watch_dir}")
    # Verify actual directory listing works (catches Windows ACL denials that os.access can miss)
    os.listdir(watch_dir)


def main():
    global running, last_error_message, session_started_at, SANDBOX_DIR

    watch_target = config.watch_paths[0] if config.watch_paths else "data/sandbox"
    SANDBOX_DIR = os.path.abspath(watch_target)

    if not acquire_process_lock():
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, signal_handler)

    try:
        init_db()
    except Exception as ex:
        last_error_message = f"Database initialization failed: {ex}"
        logger.exception(f"[Daemon] {last_error_message}")
        update_status_file(is_monitoring=False, pid=os.getpid(), observer_alive=False, error=last_error_message)
        release_process_lock()
        sys.exit(1)

    try:
        os.makedirs(SANDBOX_DIR, exist_ok=True)
        verify_watch_directory(SANDBOX_DIR)
    except Exception as ex:
        last_error_message = f"Monitored directory inaccessible ({SANDBOX_DIR}): {ex}"
        logger.exception(f"[Daemon] {last_error_message}")
        update_status_file(is_monitoring=False, pid=os.getpid(), observer_alive=False, error=last_error_message)
        release_process_lock()
        sys.exit(1)

    session_started_at = datetime.now().isoformat()
    logger.info(f"[Daemon] Starting RDRS Watchdog Daemon (PID: {os.getpid()}) monitoring: {SANDBOX_DIR}")

    handler = RDRSFileEventHandler(watch_dir=SANDBOX_DIR, event_callback=event_callback)
    observer = Observer()
    try:
        observer.schedule(handler, path=SANDBOX_DIR, recursive=True)
        observer.start()
    except Exception as ex:
        last_error_message = f"Failed to start observer: {ex}"
        logger.exception(f"[Daemon] {last_error_message}")
        update_status_file(is_monitoring=False, pid=os.getpid(), observer_alive=False, error=last_error_message)
        release_process_lock()
        sys.exit(1)

    update_status_file(is_monitoring=True, pid=os.getpid(), observer_alive=True)

    try:
        while running:
            time.sleep(2.0)
            if not running:
                break
            is_obs_alive = observer.is_alive() if hasattr(observer, "is_alive") else True
            obs_err = getattr(observer, "last_error", None)
            if not is_obs_alive or obs_err:
                last_error_message = obs_err or "Observer thread terminated unexpectedly"
                logger.error(f"[Daemon] {last_error_message}")
                update_status_file(is_monitoring=False, pid=os.getpid(), observer_alive=False, error=last_error_message)
                break

            try:
                verify_watch_directory(SANDBOX_DIR)
            except Exception as ex:
                last_error_message = f"Monitored directory lost or inaccessible ({SANDBOX_DIR}): {ex}"
                logger.exception(f"[Daemon] {last_error_message}")
                update_status_file(is_monitoring=False, pid=os.getpid(), observer_alive=False, error=last_error_message)
                break

            update_status_file(is_monitoring=True, pid=os.getpid(), observer_alive=True)
    except Exception as ex:
        logger.exception(f"[Daemon] Loop exception: {ex}")
        last_error_message = str(ex)
    finally:
        logger.info("[Daemon] Stopping Watchdog Observer...")
        update_status_file(is_monitoring=False, pid=None, observer_alive=False, error=last_error_message)
        try:
            observer.stop()
            observer.join(timeout=3)
        except Exception as ex:
            logger.warning(f"[Daemon] Error stopping observer: {ex}")
        release_process_lock()
        logger.info("[Daemon] Shutdown complete.")


if __name__ == "__main__":
    main()

