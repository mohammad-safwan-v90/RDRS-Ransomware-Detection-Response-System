"""
Real-Time File System Monitor with SQLite Event Persistence
Supports Watchdog with pure-Python Fallback and Event Deduplication
"""

import os
import sys
import time
import threading
import sqlite3
from datetime import datetime
from typing import Callable, List, Optional, Dict
from rdrs.app.core.entropy import calculate_file_entropy
from rdrs.app.core.logging_config import logger
from rdrs.app.database.db import get_db_connection

try:
    from watchdog.observers import Observer as WatchdogObserver
    from watchdog.events import FileSystemEventHandler as WatchdogFileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
    WatchdogObserver = None
    WatchdogFileSystemEventHandler = object


class BaseEventHandler:
    def __init__(self, watch_dir: str, event_callback: Optional[Callable[[dict], None]] = None):
        self.watch_dir = os.path.abspath(watch_dir)
        self.reset_flag_path = os.path.join(
            os.path.dirname(self.watch_dir),
            ".rdrs_reset_in_progress"
        )
        self.event_callback = event_callback
        self._last_events: Dict[str, float] = {}

    def should_ignore(self, path: str) -> bool:
        if not path:
            return True
        norm_path = path.replace("\\", "/")
        basename = os.path.basename(norm_path)
        ext = os.path.splitext(basename)[1].lower()
        if "/.git" in norm_path or "/__pycache__" in norm_path or basename in ("monitor_status.json", "rdrs_daemon.lock"):
            return True
        if ext in (".db", ".db-wal", ".db-shm", ".tmp", ".lock") or basename.endswith(".db-wal") or basename.endswith(".db-shm"):
            return True
        return False

    def handle_event(self, event_type: str, file_path: str, dest_path: Optional[str] = None):
        if self.should_ignore(file_path):
            return
        if os.path.exists(self.reset_flag_path):
            return

        if os.path.exists(file_path) and os.path.isdir(file_path):
            return

        now_ts = time.time()
        if len(self._last_events) > 1000:
            cutoff_ts = now_ts - 60.0
            self._last_events = {k: v for k, v in self._last_events.items() if v >= cutoff_ts}
        dedup_key = f"{event_type}:{file_path}"
        if dedup_key in self._last_events and (now_ts - self._last_events[dedup_key]) < 0.3:
            return
        self._last_events[dedup_key] = now_ts

        ext = os.path.splitext(file_path)[1].lower()
        if event_type == "deleted" or not os.path.exists(file_path):
            entropy = 0.0
        else:
            try:
                entropy = calculate_file_entropy(file_path)
            except Exception:
                entropy = 0.0

        now_str = datetime.now().isoformat()
        event_data = {
            "timestamp": now_str,
            "event_type": event_type,
            "file_path": file_path,
            "dest_path": dest_path,
            "extension": ext,
            "entropy": entropy
        }

        
        conn = None
        try:
            # Do not persist events while a sandbox reset is running.
            if os.path.exists(self.reset_flag_path):
                return

            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO file_events (timestamp, event_type, file_path, dest_path, extension, entropy, process_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (now_str, event_type, file_path, dest_path, ext, entropy, None))
            conn.commit()
        except Exception as ex:
            logger.exception(f"Failed to insert file event into SQLite DB: {ex}")
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass


        logger.info(f"File Event [{event_type.upper()}]: {file_path} (Entropy: {entropy:.2f})")

        if self.event_callback:
            try:
                self.event_callback(event_data)
            except Exception as ex:
                logger.exception(f"Error in event_callback: {ex}")


if HAS_WATCHDOG:
    class RDRSFileEventHandler(WatchdogFileSystemEventHandler, BaseEventHandler):
        def __init__(self, watch_dir: str, event_callback: Optional[Callable[[dict], None]] = None):
            WatchdogFileSystemEventHandler.__init__(self)
            BaseEventHandler.__init__(self, watch_dir, event_callback)

        def on_created(self, event):
            if not event.is_directory:
                self.handle_event("created", event.src_path)

        def on_modified(self, event):
            if not event.is_directory:
                self.handle_event("modified", event.src_path)

        def on_deleted(self, event):
            if not event.is_directory:
                self.handle_event("deleted", event.src_path)

        def on_moved(self, event):
            if not event.is_directory:
                self.handle_event("renamed", event.src_path, getattr(event, "dest_path", None))
else:
    class RDRSFileEventHandler(BaseEventHandler):
        def __init__(self, watch_dir: str, event_callback: Optional[Callable[[dict], None]] = None):
            super().__init__(watch_dir, event_callback)

        def on_created(self, file_path: str):
            self.handle_event("created", file_path)

        def on_modified(self, file_path: str):
            self.handle_event("modified", file_path)

        def on_deleted(self, file_path: str):
            self.handle_event("deleted", file_path)

        def on_moved(self, src_path: str, dest_path: str):
            self.handle_event("renamed", src_path, dest_path)


class FallbackObserver:
    """Pure-Python directory polling observer used when watchdog package is absent."""
    def __init__(self):
        self._handler = None
        self._watch_dir = None
        self._running = False
        self._thread = None
        self._snapshot: Dict[str, float] = {}
        self.last_error: Optional[str] = None

    def schedule(self, event_handler, path: str, recursive: bool = True):
        self._handler = event_handler
        self._watch_dir = os.path.abspath(path)

    def start(self):
        if not self._watch_dir or not os.path.isdir(self._watch_dir) or not os.access(self._watch_dir, os.R_OK):
            raise OSError(f"Monitored directory is missing or inaccessible: {self._watch_dir}")
        self.last_error = None
        self._running = True
        self._snapshot = self._scan_state()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def is_alive(self) -> bool:
        return bool(self._running and self._thread and self._thread.is_alive())

    def _scan_state(self) -> Dict[str, float]:
        state = {}
        if not self._watch_dir or not os.path.isdir(self._watch_dir) or not os.access(self._watch_dir, os.R_OK):
            raise OSError(f"Monitored directory unavailable: {self._watch_dir}")
        for root, _, files in os.walk(self._watch_dir):
            for f in files:
                full_p = os.path.join(root, f)
                if self._handler and self._handler.should_ignore(full_p):
                    continue
                try:
                    state[full_p] = os.path.getmtime(full_p)
                except OSError:
                    pass
        return state

    def _poll_loop(self):
        try:
            while self._running:
                time.sleep(0.5)
                if not self._running:
                    break
                current_state = self._scan_state()
                # Detect created or modified
                for path, mtime in current_state.items():
                    if path not in self._snapshot:
                        if self._handler:
                            self._handler.on_created(path) if not HAS_WATCHDOG else self._handler.handle_event("created", path)
                    elif mtime > self._snapshot[path]:
                        if self._handler:
                            self._handler.on_modified(path) if not HAS_WATCHDOG else self._handler.handle_event("modified", path)
                # Detect deleted
                for path in list(self._snapshot.keys()):
                    if path not in current_state:
                        if self._handler:
                            self._handler.on_deleted(path) if not HAS_WATCHDOG else self._handler.handle_event("deleted", path)
                self._snapshot = current_state
        except Exception as ex:
            self.last_error = str(ex)
            self._running = False
            logger.exception(f"[FallbackObserver] Polling stopped due to error: {ex}")

    def stop(self):
        self._running = False

    def join(self, timeout=None):
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)



Observer = WatchdogObserver if HAS_WATCHDOG else FallbackObserver


class FileMonitor:
    def __init__(self, watch_paths: List[str], event_callback: Optional[Callable[[dict], None]] = None):
        self.watch_paths = watch_paths
        self.event_callback = event_callback
        self.is_running = False

    def scan_directory(self, target_dir: str) -> List[dict]:
        events = []
        if not os.path.exists(target_dir):
            os.makedirs(target_dir, exist_ok=True)

        for root, _, files in os.walk(target_dir):
            for file in files:
                full_path = os.path.join(root, file)
                if ".git" in full_path or ".db" in full_path:
                    continue
                ext = os.path.splitext(file)[1].lower()
                ent = calculate_file_entropy(full_path)
                events.append({
                    "timestamp": datetime.now().isoformat(),
                    "event_type": "scanned",
                    "file_path": full_path,
                    "extension": ext,
                    "entropy": ent
                })
        return events
