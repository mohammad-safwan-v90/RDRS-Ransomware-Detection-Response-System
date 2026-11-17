"""
RDRS Python Backend API Layer
Queries SQLite database directly and handles alert/incident state mutations.
"""

import os
import sys
import json
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from rdrs.app.core.config import config
from rdrs.app.core.entropy import calculate_file_entropy, calculate_shannon_entropy
from rdrs.app.core.logging_config import logger
from rdrs.app.database.db import get_db_connection, init_db
from rdrs.app.detectors.detection_engine import DetectionEngine
from rdrs.app.reports.report_generator import ReportGenerator

init_db()

detection_engine = DetectionEngine()
report_generator = ReportGenerator()


def _is_process_alive(pid: int) -> bool:
    """
    Cross-platform non-signaling process liveness check.
    On Windows, os.kill(pid, 0) passes 0 (CTRL_C_EVENT) to GenerateConsoleCtrlEvent,
    which can trigger console SIGINT propagation instead of checking PID existence.
    """
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False

    if sys.platform.startswith("win"):
        try:
            import psutil
            if not psutil.pid_exists(pid):
                return False
            try:
                proc = psutil.Process(pid)
                return proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
            except psutil.AccessDenied:
                return True
            except psutil.NoSuchProcess:
                return False
        except ImportError:
            pass

        try:
            import ctypes
            process_query_limited_info = 0x1000
            error_access_denied = 5
            still_active = 259

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(process_query_limited_info, False, pid)
            if not handle:
                return kernel32.GetLastError() == error_access_denied
            try:
                exit_code = ctypes.c_ulong()
                if kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                    return exit_code.value == still_active
                return False
            finally:
                kernel32.CloseHandle(handle)
        except Exception:
            return False

    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except (OSError, ProcessLookupError):
        return False


def check_daemon_health(status_file_path: Optional[str] = None) -> Dict[str, Any]:
    from rdrs_daemon import STATUS_FILE
    target_path = os.path.abspath(status_file_path) if status_file_path else STATUS_FILE
    if not os.path.exists(target_path):
        return {"is_monitoring": False, "pid": None, "reason": "No status file"}

    try:
        with open(target_path, "r") as f:
            data = json.load(f)
    except Exception as ex:
        return {"is_monitoring": False, "pid": None, "reason": f"Corrupt status file: {ex}"}

    if not data.get("is_monitoring") or data.get("observer_alive") is False:
        reason = data.get("last_error") or "Monitoring marked false or observer dead"
        if data.get("last_error") and "Monitoring marked false" not in reason:
            reason = f"Monitoring marked false or observer dead: {data.get('last_error')}"
        return {"is_monitoring": False, "pid": None, "reason": reason}

    pid = data.get("pid")
    if pid is None:
        return {"is_monitoring": False, "pid": None, "reason": "Missing daemon PID"}
    if not _is_process_alive(pid):
        return {"is_monitoring": False, "pid": pid, "reason": "Process dead"}

    last_hb_str = data.get("last_heartbeat")
    if not last_hb_str or not isinstance(last_hb_str, str):
        return {"is_monitoring": False, "pid": pid, "reason": "Missing heartbeat"}

    try:
        hb_dt = datetime.fromisoformat(last_hb_str)
        now_dt = datetime.now(hb_dt.tzinfo) if hb_dt.tzinfo is not None else datetime.now()
        if (now_dt - hb_dt).total_seconds() > 10.0:
            return {"is_monitoring": False, "pid": pid, "reason": "Stale heartbeat"}
    except (ValueError, TypeError):
        return {"is_monitoring": False, "pid": pid, "reason": "Invalid heartbeat timestamp"}

    return {"is_monitoring": True, "pid": pid, "reason": "Healthy"}


def _get_system_cpu_usage() -> float:
    try:
        import psutil
        return round(float(psutil.cpu_percent(interval=0.05)), 1)
    except Exception:
        pass
    try:
        if hasattr(os, "getloadavg"):
            load1 = os.getloadavg()[0]
            cpus = os.cpu_count() or 1
            return round(min(100.0, (load1 / cpus) * 100.0), 1)
    except Exception:
        pass
    return 0.0


def get_real_health(status_file_path: Optional[str] = None) -> Dict[str, Any]:
    health = check_daemon_health(status_file_path=status_file_path)
    db_ok = False
    db_error = None
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        db_ok = True
    except Exception as ex:
        db_error = str(ex)
        logger.exception(f"Health check database connectivity error: {ex}")
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    overall_status = "healthy" if (health["is_monitoring"] and db_ok) else "degraded"
    return {
        "status": overall_status,
        "service": "RDRS Python Detection Core (Live SSE Stream Ready)",
        "daemon_monitoring": health["is_monitoring"],
        "daemon_pid": health.get("pid"),
        "daemon_reason": health.get("reason"),
        "database_accessible": db_ok,
        "database_error": db_error,
        "config_loaded": getattr(config, "config_loaded", True),
        "config_warning": getattr(config, "config_error", None),
        "simulation_mode": config.simulation_mode,
        "timestamp": datetime.now().isoformat()
    }


def get_real_system_status() -> Dict[str, Any]:
    conn = get_db_connection()
    try:
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) as cnt FROM file_events")
        total_events = cur.fetchone()["cnt"]

        cur.execute("SELECT COUNT(*) as cnt FROM alerts WHERE status != 'Resolved'")
        active_alerts = cur.fetchone()["cnt"]

        cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 1")
        latest_alert = cur.fetchone()

        cur.execute("SELECT AVG(entropy) as avg_ent FROM file_events WHERE entropy > 0")
        avg_ent_row = cur.fetchone()
        raw_avg = avg_ent_row["avg_ent"]
        avg_entropy = round(raw_avg, 2) if raw_avg is not None else 0.0
    finally:
        conn.close()

    if latest_alert:
        threat_score = latest_alert["threat_score"]
        threat_level = latest_alert["severity"]
    else:
        threat_score = 0
        threat_level = "Normal"

    health = check_daemon_health()

    return {
        "threat_level": threat_level,
        "threat_score": threat_score,
        "active_alerts_count": active_alerts,
        "total_events_count": total_events,
        "is_monitoring": health["is_monitoring"],
        "daemon_pid": health.get("pid"),
        "daemon_reason": health.get("reason"),
        "simulation_mode": config.simulation_mode,
        "cpu_usage": _get_system_cpu_usage(),
        "avg_entropy": avg_entropy,
        "last_updated": datetime.now().strftime("%d %b %Y, %H:%M:%S")
    }


def get_real_alerts(severity_filter: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        if severity_filter and severity_filter != "All":
            cur.execute("SELECT * FROM alerts WHERE severity = ? ORDER BY id DESC LIMIT ?", (severity_filter, limit))
        else:
            cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

    alerts = []
    for r in rows:
        try:
            signals = json.loads(r["detection_signals"])
        except Exception:
            signals = [r["detection_signals"]]
        try:
            affected = json.loads(r["affected_files"])
        except Exception:
            affected = [r["affected_files"]]

        alerts.append({
            "id": r["id"],
            "time": r["timestamp"].split("T")[-1][:8] if "T" in r["timestamp"] else r["timestamp"],
            "timestamp": r["timestamp"],
            "severity": r["severity"],
            "message": r["message"],
            "threat_score": r["threat_score"],
            "status": r.get("status", "Unacknowledged"),
            "detection_signals": signals,
            "affected_files": affected
        })
    return alerts


def update_alert_status(alert_id: int, new_status: str) -> Dict[str, Any]:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE alerts SET status = ? WHERE id = ?", (new_status, alert_id))
        updated = cur.rowcount
        conn.commit()
    finally:
        conn.close()
    if updated == 0:
        return {"error": f"Alert #{alert_id} not found", "status_code": 404}
    return {"status": "success", "alert_id": alert_id, "new_status": new_status}


def get_real_events(event_type_filter: Optional[str] = None, search: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        cur = conn.cursor()

        query = "SELECT * FROM file_events WHERE 1=1"
        params = []

        if event_type_filter and event_type_filter != "All":
            query += " AND event_type = ?"
            params.append(event_type_filter.lower())

        if search:
            query += " AND file_path LIKE ?"
            params.append(f"%{search}%")

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        cur.execute(query, params)
        rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    return rows


def get_real_incidents() -> Dict[str, Any]:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
    finally:
        conn.close()

    if not row:
        return {
            "incident_id": "INC-NONE",
            "timestamp": datetime.now().isoformat(),
            "threat_score": 0,
            "severity": "Normal",
            "affected_files_count": 0,
            "affected_files": [],
            "process": {"name": "python.exe", "pid": 0},
            "detection_signals": ["No active critical incidents"],
            "status": "Normal Operation",
            "quarantine_paths": []
        }

    inc = dict(row)
    try:
        inc["affected_files"] = json.loads(inc["affected_files"])
    except Exception:
        inc["affected_files"] = []
    try:
        inc["detection_signals"] = json.loads(inc["detection_signals"])
    except Exception:
        inc["detection_signals"] = []
    try:
        inc["quarantine_paths"] = json.loads(inc["quarantine_paths"])
    except Exception:
        inc["quarantine_paths"] = []

    inc["process"] = {"name": inc.get("process_name", "python.exe"), "pid": inc.get("process_pid", 0)}
    return inc


def update_incident_status(incident_id: str, new_status: str) -> Dict[str, Any]:
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE incidents SET status = ? WHERE incident_id = ?", (new_status, incident_id))
        updated = cur.rowcount
        conn.commit()
    finally:
        conn.close()
    if updated == 0:
        return {"error": f"Incident '{incident_id}' not found", "status_code": 404}
    return {"status": "success", "incident_id": incident_id, "new_status": new_status}


def run_sandbox_simulation(attack_type: str) -> Dict[str, Any]:
    sandbox_dir = config.watch_paths[0] if config.watch_paths else "./data/sandbox"
    os.makedirs(sandbox_dir, exist_ok=True)
    now_str = datetime.now().isoformat()

    if attack_type == "create_normal":
        created_files = []
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            for i in range(5):
                fname = f"document_{i}.txt"
                fpath = os.path.join(sandbox_dir, fname)
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(f"Normal unencrypted source code or documentation text line {i}.")

                ent = calculate_file_entropy(fpath)
                cur.execute("""
                    INSERT INTO file_events (timestamp, event_type, file_path, extension, entropy)
                    VALUES (?, ?, ?, ?, ?)
                """, (now_str, "created", fpath, ".txt", ent))
                created_files.append(fpath)

            conn.commit()
        finally:
            conn.close()
            
        message = f"Created {len(created_files)} normal plain text files in sandbox (Low entropy ~3.5)."
        
    elif attack_type in ("entropy_spike", "full_simulation"):
        created_files = []
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            for i in range(15):
                fname = f"financial_data_{i}.locked"
                fpath = os.path.join(sandbox_dir, fname)

                with open(fpath, "wb") as f:
                    f.write(os.urandom(2048))

                ent = calculate_file_entropy(fpath)

                event_type = (
                    "created" if attack_type == "entropy_spike"
                    else "modified"
                )

                cur.execute("""
                    INSERT INTO file_events
                    (timestamp, event_type, file_path, extension, entropy)
                    VALUES (?, ?, ?, ?, ?)
                """, (now_str, event_type, fpath, ".locked", ent))

                created_files.append(fpath)

            conn.commit()
        finally:
            conn.close()

        events = [
            {
                "timestamp": now_str,
                "event_type": (
                    "created" if attack_type == "entropy_spike"
                    else "modified"
                ),
                "file_path": p,
                "entropy": calculate_file_entropy(p)
            }
            for p in created_files
        ]

        if attack_type == "full_simulation":
            proc = {
                "name": "python.exe",
                "pid": os.getpid(),
                "cpu_percent": 88.5,
                "is_suspicious": True
            }
            result = detection_engine.analyze_events(
                events, process_info=proc
            )
            message = (
                f"Full ransomware simulation complete. "
                f"Threat Score: {result['threat_score']}/100."
            )
        else:
            result = detection_engine.analyze_events(events)
            message = (
                f"High-entropy-only simulation complete. "
                f"Threat Score: {result['threat_score']}/100."
            )

        report_generator.generate_all_reports_from_db()


    

    
    elif attack_type == "mass_rename":
        conn = get_db_connection()
        events = []

        try:
            cur = conn.cursor()

            for i in range(10):
                old_p = os.path.join(sandbox_dir, f"report_{i}.docx")
                new_p = os.path.join(sandbox_dir, f"report_{i}.docx.locked")

                # Create an ordinary readable document
                with open(old_p, "w", encoding="utf-8") as f:
                    f.write(
                        f"Normal readable business report number {i}. "
                        "This is ordinary unencrypted document content."
                    )

                # Measure entropy before renaming
                ent = calculate_file_entropy(old_p)

                # Perform a real filesystem rename
                os.rename(old_p, new_p)

                # Persist the actual rename event
                cur.execute("""
                    INSERT INTO file_events
                    (timestamp, event_type, file_path, dest_path, extension, entropy)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (now_str, "renamed", old_p, new_p, ".locked", ent))

                events.append({
                    "timestamp": now_str,
                    "event_type": "renamed",
                    "file_path": old_p,
                    "dest_path": new_p,
                    "entropy": ent
                })

            conn.commit()

        finally:
            conn.close()

        result = detection_engine.analyze_events(events)

        message = (
            f"Real mass file renaming simulation complete. "
            f"Threat Score: {result['threat_score']}/100."
        )


    
    elif attack_type == "reset":
        reset_flag_path = os.path.join(
            os.path.dirname(os.path.abspath(sandbox_dir)),
            ".rdrs_reset_in_progress"
        )

        try:
            # Signal the file monitor to ignore events during reset.
            with open(reset_flag_path, "w", encoding="utf-8") as flag:
                flag.write("reset")

            # Step 1: Delete sandbox files.
            if os.path.exists(sandbox_dir):
                for filename in os.listdir(sandbox_dir):
                    fp = os.path.join(sandbox_dir, filename)
                    if os.path.isfile(fp):
                        try:
                            os.remove(fp)
                        except OSError as ex:
                            logger.warning(
                                f"Could not remove sandbox file '{fp}': {ex}"
                            )

            # Step 2: Allow Watchdog to process pending events.
            time.sleep(25.0)

            # Step 3: Clear SQLite records.
            conn = get_db_connection()
            try:
                cur = conn.cursor()
                cur.execute("DELETE FROM alerts")
                cur.execute("DELETE FROM file_events")
                cur.execute("DELETE FROM incidents")
                conn.commit()
            finally:
                conn.close()

            message = "Sandbox files & SQLite records reset to clean state."

        finally:
            # Always remove the reset flag, even if reset fails.
            if os.path.exists(reset_flag_path):
                os.remove(reset_flag_path)


        

    else:
        return {"error": f"Unknown attack type: {attack_type}", "status_code": 400}

    return {"status": "success", "message": message, "systemState": get_real_system_status()}


def get_real_threat_history(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Returns historical threat scores from the alerts table for the last 24 hours.
    """
    conn = get_db_connection()
    try:
        cur = conn.cursor()

        # 1. Filter for the last 24 hours (Requirement 3)
        day_ago = (datetime.now() - timedelta(hours=24)).isoformat()

        # Query latest alerts within the time window.
        cur.execute("""
            SELECT timestamp, threat_score 
            FROM alerts 
            WHERE timestamp >= ? 
            ORDER BY id DESC 
            LIMIT ?
        """, (day_ago, limit))

        rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

    history = []
    # Reverse to show chronological order (left-to-right)
    for r in reversed(rows):
        ts = r["timestamp"]
        # Extract HH:MM from ISO timestamp
        time_str = ts.split("T")[-1][:5] if "T" in ts else ts[:5]
        history.append({
            "time": time_str,
            "score": r["threat_score"],
            "full_timestamp": ts
        })

    # Requirement: "When no records exist, display a truthful empty state."
    return history

