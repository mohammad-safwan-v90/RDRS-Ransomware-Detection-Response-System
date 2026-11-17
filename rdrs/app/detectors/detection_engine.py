"""
Ransomware Detection Engine & Threat Scoring Matrix
Evaluates file events & process telemetry over a sliding time window.
Calculates a weighted Threat Score (0–100), persists to SQLite, and executes defensive quarantine actions.
"""

import os
import shutil
import json
import sqlite3
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from rdrs.app.core.config import config
from rdrs.app.core.entropy import calculate_file_entropy
from rdrs.app.core.logging_config import logger
from rdrs.app.database.db import get_db_connection


class DetectionEngine:
    def __init__(self):
        self.weights = config.weights
        self.entropy_threshold = config.entropy_threshold
        self.time_window_seconds = config.time_window_seconds
        self.quarantine_dir = config.get("quarantine", {}).get("storage_dir", "./quarantine")
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def analyze_events(
        self,
        events: List[Dict[str, Any]],
        process_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Analyze recent file events within the sliding time window and compute threat metrics.
        """
        now = datetime.now()
        window_start = now - timedelta(seconds=self.time_window_seconds)

        recent_events = []
        seen_event_keys = set()
        for event in events:
            dedup_key = (
                event.get("timestamp"),
                event.get("event_type"),
                event.get("file_path"),
                event.get("dest_path")
            )
            if dedup_key in seen_event_keys:
                continue
            seen_event_keys.add(dedup_key)
            try:
                evt_time = datetime.fromisoformat(event["timestamp"])
                if evt_time >= window_start:
                    recent_events.append(event)
            except (ValueError, KeyError, TypeError):
                recent_events.append(event)

        # Count unique modified files, excluding files created in this window.
        created_paths = {
            os.path.normcase(os.path.normpath(e["file_path"]))
            for e in recent_events
            if e.get("event_type") == "created" and e.get("file_path")
        }
        
        modified_paths = {
            os.path.normcase(os.path.normpath(e["file_path"]))
            for e in recent_events
            if e.get("event_type") == "modified"
            and e.get("file_path")
            and os.path.normcase(os.path.normpath(e["file_path"])) not in created_paths
        }
        
        modifications_count = len(modified_paths)
        
        
        renames_count = sum(
            1 for e in recent_events
            if e.get("event_type") == "renamed"
        )

        high_entropy_count = sum(1 for e in recent_events if e.get("entropy", 0.0) >= self.entropy_threshold)

        signals = []
        raw_score = 0

        # Signal 1: Rapid encryption activity
        if modifications_count >= config.get("detection", {}).get("rapid_mods_threshold", 15):
            signals.append("Rapid encryption-like activity")
            raw_score += self.weights.get("rapid_encryption", 40)

        # Signal 2: Mass file renaming
        if renames_count >= config.get("detection", {}).get("mass_rename_threshold", 8):
            signals.append("Mass file renaming")
            raw_score += self.weights.get("mass_rename", 30)

        # Signal 3: High entropy content
        if high_entropy_count > 0:
            signals.append(f"High file entropy detected ({high_entropy_count} files >= {self.entropy_threshold})")
            raw_score += self.weights.get("high_entropy", 25)

        # Signal 4: CPU spike
        cpu_percent = process_info.get("cpu_percent", 0.0) if process_info else 0.0
        if cpu_percent >= config.get("detection", {}).get("cpu_spike_threshold", 75.0):
            signals.append(f"CPU spike detected ({cpu_percent:.1f}%)")
            raw_score += self.weights.get("cpu_spike", 15)

        # Signal 5: Unknown/suspicious process metadata
        if process_info and process_info.get("is_suspicious", False):
            signals.append(f"Suspicious process metadata: {process_info.get('name')}")
            raw_score += self.weights.get("unknown_program", 10)

        # Threat Score capped at 100
        threat_score = min(100, raw_score)

        if threat_score >= 70:
            severity = "Critical"
        elif threat_score >= 40:
            severity = "Warning"
        else:
            severity = "Normal"

        renamed_sources = {
            e.get("file_path")
            for e in recent_events
            if e.get("event_type") == "renamed" and e.get("file_path")
        }
        
        affected_file_set = set()
        
        for event in recent_events:
            path = event.get("file_path")
            
            if not path:
                continue
            
            if event.get("event_type") == "renamed":
                path = event.get("dest_path") or path
            elif path in renamed_sources:
                continue
            
            affected_file_set.add(path)
        
        affected_files = sorted(affected_file_set)

        eval_result = {
            "threat_score": threat_score,
            "severity": severity,
            "detection_signals": signals,
            "affected_files": affected_files,
            "recent_events_count": len(recent_events),
            "modifications_count": modifications_count,
            "renames_count": renames_count,
            "high_entropy_count": high_entropy_count,
            "process_info": process_info
        }

        # Persist alert & incident into SQLite if Warning or Critical
        if severity in ("Warning", "Critical"):
            self._record_incident(eval_result)

        return eval_result

    def _record_incident(self, eval_result: Dict[str, Any]):
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            now_str = datetime.now().isoformat()
            signals_json = json.dumps(eval_result["detection_signals"])
            files_json = json.dumps(eval_result["affected_files"])

            # Insert Alert
            cur.execute("""
                INSERT INTO alerts (timestamp, severity, threat_score, message, detection_signals, affected_files)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                now_str,
                eval_result["severity"],
                eval_result["threat_score"],
                f"{eval_result['severity']} Threat: {', '.join(eval_result['detection_signals'])}",
                signals_json,
                files_json
            ))

            # Quarantine evidence
            quarantine_paths = self.quarantine_evidence(eval_result["affected_files"])

            # Insert Incident if Critical
            if eval_result["severity"] == "Critical":
                inc_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{cur.lastrowid:04d}"
                proc = eval_result.get("process_info") or {}
                cur.execute("""
                    INSERT OR REPLACE INTO incidents (incident_id, timestamp, threat_score, severity, affected_files_count, affected_files, process_name, process_pid, detection_signals, status, quarantine_paths)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    inc_id,
                    now_str,
                    eval_result["threat_score"],
                    eval_result["severity"],
                    len(eval_result["affected_files"]),
                    files_json,
                    proc.get("name", "unknown_proc.exe"),
                    proc.get("pid", 0),
                    signals_json,
                    "Contained (Simulation)",
                    json.dumps(quarantine_paths)
                ))

            conn.commit()
        except Exception as ex:
            try:
                conn.rollback()
            except Exception:
                pass
            logger.exception(f"Failed to persist alert/incident to SQLite: {ex}")
            raise
        finally:
            conn.close()


    def quarantine_evidence(self, file_paths: List[str]) -> List[str]:
        quarantined = []
        timestamp_prefix = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Security: Resolve absolute canonical paths for all configured watch paths
        allowed_roots = [os.path.realpath(p) for p in config.watch_paths]

        for src_path in file_paths:
            if not src_path:
                continue
            
            # 1. Resolve canonical path (resolves symlinks and removes ..)
            try:
                abs_src = os.path.realpath(src_path)
            except Exception:
                continue

            # 2. Reject nonexistent files (Requirement 6)
            if not os.path.exists(abs_src):
                logger.warning(f"Security Block: File does not exist: {abs_src}")
                continue

            # 3. Reject if not a file
            if not os.path.isfile(abs_src):
                continue

            # 4. Strict Containment Check (Requirement 3 & 5)
            is_allowed = False
            for root in allowed_roots:
                try:
                    # commonpath returns the common prefix; it must exactly match the root for containment
                    if os.path.commonpath([root]) == os.path.commonpath([root, abs_src]):
                        is_allowed = True
                        break
                except Exception:
                    continue
            
            if not is_allowed:
                logger.warning(f"Security Block: Attempted to quarantine file outside sandbox: {abs_src}")
                continue

            # 5. Quarantine evidence (Requirement 8)
            try:
                filename = os.path.basename(abs_src)
                dest_name = f"{timestamp_prefix}_{filename}"
                dest = os.path.join(self.quarantine_dir, dest_name)
                
                # Check for duplicate quarantine (avoiding unnecessary copies in same batch)
                if dest not in quarantined:
                    shutil.copy2(abs_src, dest)
                    quarantined.append(dest)
            except Exception as ex:
                logger.warning(f"Failed to quarantine file {abs_src}: {ex}")
        
        return quarantined
