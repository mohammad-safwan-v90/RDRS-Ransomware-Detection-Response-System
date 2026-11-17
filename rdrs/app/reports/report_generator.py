"""
RDRS Report Generator - Reads real SQLite records to generate CSV, JSON, and HTML reports
"""

import os
import csv
import html
import json
import sqlite3
from datetime import datetime
from typing import Dict, Any, List
from rdrs.app.database.db import get_db_connection


class ReportGenerator:
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_all_reports_from_db(self) -> List[str]:
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM incidents ORDER BY id DESC")
            rows = [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()


        generated_files = []

        if rows:
            latest = rows[0]
            # Parse JSON strings
            try:
                latest["affected_files"] = json.loads(latest["affected_files"])
            except Exception:
                latest["affected_files"] = []

            try:
                latest["detection_signals"] = json.loads(latest["detection_signals"])
            except Exception:
                latest["detection_signals"] = []

            json_p = self.generate_json_report(latest)
            html_p = self.generate_html_report(latest)
            generated_files.extend([json_p, html_p])

        csv_p = self.generate_csv_report(rows)
        generated_files.append(csv_p)
        return generated_files

    def generate_json_report(self, incident_data: Dict[str, Any]) -> str:
        if not isinstance(incident_data, dict):
            raise ValueError("incident_data must be a dictionary")
        raw_id = str(incident_data.get('incident_id') or 'INC-001')
        safe_filename_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in raw_id)
        filename = f"incident_{safe_filename_id}.json"
        filepath = os.path.join(self.output_dir, filename)

        payload = {
            "title": "Ransomware Incident Report",
            "generated_at": datetime.now().isoformat(),
            "incident": incident_data,
            "response_recommendations": [
                "Isolate compromised host machine from network",
                "Quarantine affected files for cryptographic analysis",
                "Review suspicious parent process PID and process tree",
                "Verify backup integrity and restore unencrypted files"
            ]
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        return filepath

    def generate_csv_report(self, incidents: List[Dict[str, Any]]) -> str:
        if not isinstance(incidents, list):
            raise ValueError("incidents must be a list of dictionaries")
        filename = f"incidents_summary_{datetime.now().strftime('%Y%m%d')}.csv"
        filepath = os.path.join(self.output_dir, filename)

        fieldnames = ["incident_id", "timestamp", "threat_score", "severity", "affected_files_count", "process_name", "process_pid", "status"]

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for inc in incidents:
                if not isinstance(inc, dict):
                    raise ValueError("Each item in incidents must be a dictionary")
                writer.writerow({
                    "incident_id": inc.get("incident_id", "N/A"),
                    "timestamp": inc.get("timestamp", "N/A"),
                    "threat_score": inc.get("threat_score", 0),
                    "severity": inc.get("severity", "Normal"),
                    "affected_files_count": inc.get("affected_files_count", 0),
                    "process_name": inc.get("process_name", "N/A"),
                    "process_pid": inc.get("process_pid", 0),
                    "status": inc.get("status", "Contained (Simulation)")
                })

        return filepath

    def generate_html_report(self, incident_data: Dict[str, Any]) -> str:
        if not isinstance(incident_data, dict):
            raise ValueError("incident_data must be a dictionary")
        raw_id = str(incident_data.get('incident_id') or 'INC-001')
        safe_filename_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in raw_id)
        filename = f"incident_{safe_filename_id}.html"
        filepath = os.path.join(self.output_dir, filename)

        affected_files = incident_data.get("affected_files") or []
        if isinstance(affected_files, str):
            try:
                affected_files = json.loads(affected_files)
            except Exception:
                affected_files = [affected_files]

        signals = incident_data.get("detection_signals") or []
        if isinstance(signals, str):
            try:
                signals = json.loads(signals)
            except Exception:
                signals = [signals]

        files_li = "".join([f"<li><code>{html.escape(str(f), quote=True)}</code></li>" for f in affected_files])
        signals_li = "".join([f"<li>{html.escape(str(s), quote=True)}</li>" for s in signals])

        esc_id = html.escape(raw_id, quote=True)
        esc_ts = html.escape(str(incident_data.get('timestamp', '')), quote=True)
        esc_sev = html.escape(str(incident_data.get('severity', 'Normal')), quote=True)
        esc_score = html.escape(str(incident_data.get('threat_score', 0)), quote=True)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>RDRS Incident Report - {esc_id}</title>
    <style>
        body {{ font-family: system-ui, sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem; margin: 0; }}
        .card {{ background: #1e293b; border-radius: 12px; padding: 2rem; max-width: 800px; margin: 0 auto; border: 1px solid #334155; }}
        h1 {{ color: #ef4444; border-bottom: 2px solid #ef4444; padding-bottom: 0.5rem; }}
        .badge {{ display: inline-block; padding: 0.35rem 0.75rem; border-radius: 9999px; font-weight: bold; background: #ef4444; color: white; }}
        .score {{ font-size: 2rem; font-weight: 800; color: #f87171; }}
        code {{ background: #334155; padding: 0.2rem 0.4rem; border-radius: 4px; color: #38bdf8; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>RDRS Cybersecurity Incident Report</h1>
        <p><strong>Incident ID:</strong> <code>{esc_id}</code> | <strong>Timestamp:</strong> {esc_ts}</p>
        <p>Severity: <span class="badge">{esc_sev}</span> | Score: <span class="score">{esc_score}/100</span></p>
        <h3>Detection Signals</h3>
        <ul>{signals_li}</ul>
        <h3>Affected Files</h3>
        <ul>{files_li}</ul>
    </div>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        return filepath
