#!/usr/bin/env python3
"""
RDRS Phase 6 Repeatable End-to-End Sandbox Demonstration Script
Connects to the running RDRS server, verifies /api/health, performs harmless normal and
high-entropy sandbox file operations, verifies detection alerts/incidents/quarantine/reports,
and cleans up ONLY the temporary demonstration artifacts it created.
"""

import argparse
import json
import os
import shutil
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime


def request_json(base_url: str, path: str, method: str = "GET", body=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"} if body is not None else {}
    req = urllib.request.Request(f"{base_url}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read().decode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description="Run safe repeatable RDRS end-to-end demonstration")
    parser.add_argument("--base-url", default="http://127.0.0.1:3000", help="Running RDRS Express server URL")
    parser.add_argument("--keep-artifacts", action="store_true", help="Keep demo DB/files instead of cleaning up")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    session_tag = f"demo_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    demo_sandbox_dir = os.path.abspath(os.path.join("data", "sandbox", session_tag))

    # Track exact DB max IDs and existing files so cleanup removes ONLY what this run created
    db_path = os.path.abspath(os.path.join("data", "rdrs.db"))
    quarantine_before = set(os.listdir("quarantine")) if os.path.exists("quarantine") else set()
    reports_before = set(os.listdir("reports")) if os.path.exists("reports") else set()
    max_ids_before = {"file_events": 0, "alerts": 0, "incidents": 0}
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        for tbl in max_ids_before:
            row = conn.execute(f"SELECT COALESCE(MAX(id), 0) FROM {tbl}").fetchone()
            max_ids_before[tbl] = row[0] if row else 0
        conn.close()

    try:
        print("[1/7] Checking /api/health (Stage A)...")
        health = None
        for _ in range(20):
            try:
                code, health = request_json(base, "/api/health")
                if code == 200 and health.get("daemon_monitoring") and health.get("database_accessible"):
                    break
            except Exception:
                pass
            time.sleep(0.5)
        if not health or health.get("status") != "healthy":
            print(f"ERROR: RDRS server/daemon unhealthy at {base}: {health}", file=sys.stderr)
            sys.exit(1)
        print(f"   OK -> status={health['status']} pid={health['daemon_pid']} db={health['database_accessible']}")

        print(f"[2/7] Creating harmless normal files in {demo_sandbox_dir} (Stage B)...")
        os.makedirs(demo_sandbox_dir, exist_ok=True)
        normal_path = os.path.join(demo_sandbox_dir, "sample_report.txt")
        with open(normal_path, "w", encoding="utf-8") as f:
            f.write("Safe plain text coursework file for baseline Shannon entropy test.\n")
        time.sleep(0.7)
        with open(normal_path, "a", encoding="utf-8") as f:
            f.write("Appended plain text line.\n")
        time.sleep(0.7)
        renamed_path = os.path.join(demo_sandbox_dir, "sample_report_edited.txt")
        os.rename(normal_path, renamed_path)
        time.sleep(1.0)

        _, st_normal = request_json(base, "/api/status")
        _, ev_normal = request_json(base, f"/api/events?search={session_tag}")
        print(f"   OK -> normal events captured={len(ev_normal.get('events', []))}, threat_score={st_normal['threat_score']}")
        assert len(ev_normal.get("events", [])) >= 1, "Daemon did not capture sandbox text events"

        print("[3/7] Writing 15 harmless random-byte .locked files inside sandbox (Stage C & D)...")
        locked_files = []
        for i in range(15):
            lp = os.path.join(demo_sandbox_dir, f"victim_{i}.locked")
            with open(lp, "wb") as f:
                f.write(os.urandom(2048))
            locked_files.append(lp)

        time.sleep(2.5)
        _, st_crit = request_json(base, "/api/status")
        _, al_res = request_json(base, "/api/alerts")
        _, inc_res = request_json(base, "/api/incidents")
        _, hist_res = request_json(base, "/api/history")
        print(f"   OK -> severity={st_crit['threat_level']} score={st_crit['threat_score']}/100 alerts={len(al_res.get('alerts', []))}")
        assert st_crit["threat_score"] >= 70 and st_crit["threat_level"] == "Critical"
        assert inc_res["incident"]["incident_id"].startswith("INC-")
        assert len(hist_res.get("history", [])) >= 1

        print("[4/7] Verifying quarantine evidence copy & original file preservation (Stage E)...")
        originals_ok = all(os.path.exists(p) for p in locked_files)
        quarantine_after = set(os.listdir("quarantine")) if os.path.exists("quarantine") else set()
        new_quarantined = sorted(quarantine_after - quarantine_before)
        quarantined_locked = [f for f in new_quarantined if f.endswith(".locked")]
        assert originals_ok, "Simulation mode must preserve original sandbox files"
        assert len(new_quarantined) >= 10 and len(quarantined_locked) >= 8, (
            f"Expected >=10 quarantined copies (>=8 .locked), got {len(new_quarantined)} ({len(quarantined_locked)} .locked)"
        )
        print(f"   OK -> originals_preserved={originals_ok}, new_quarantine_files={len(new_quarantined)} (.locked={len(quarantined_locked)})")

        print("[5/7] Verifying SQLite persistence (Stage F)...")
        conn = sqlite3.connect(db_path)
        new_ev_cnt = conn.execute("SELECT COUNT(*) FROM file_events WHERE id > ?", (max_ids_before["file_events"],)).fetchone()[0]
        new_al_cnt = conn.execute("SELECT COUNT(*) FROM alerts WHERE id > ?", (max_ids_before["alerts"],)).fetchone()[0]
        new_inc_cnt = conn.execute("SELECT COUNT(*) FROM incidents WHERE id > ?", (max_ids_before["incidents"],)).fetchone()[0]
        latest_inc_id = conn.execute("SELECT incident_id FROM incidents ORDER BY id DESC LIMIT 1").fetchone()[0]
        conn.close()
        assert new_ev_cnt >= 16 and new_al_cnt >= 1 and new_inc_cnt >= 1
        print(f"   OK -> sqlite new_events={new_ev_cnt}, new_alerts={new_al_cnt}, new_incidents={new_inc_cnt}")

        print("[6/7] Verifying generated JSON, CSV, and HTML reports (Stage G)...")
        reports_after = set(os.listdir("reports")) if os.path.exists("reports") else set()
        new_reports = sorted(reports_after - reports_before)
        csv_files = sorted(f for f in reports_after if f.endswith(".csv"))
        assert any(f.endswith(".json") for f in new_reports), f"Expected new JSON report, got {new_reports}"
        assert any(f.endswith(".html") for f in new_reports), f"Expected new HTML report, got {new_reports}"
        assert csv_files, "Expected CSV summary report in reports/"
        with open(os.path.join("reports", csv_files[-1]), "r", encoding="utf-8") as cf:
            csv_text = cf.read()
        assert latest_inc_id in csv_text, f"Expected {latest_inc_id} in CSV report {csv_files[-1]}"
        print(f"   OK -> reports generated: new={new_reports}, csv={csv_files[-1]}")

        print("[7/7] Demonstration succeeded cleanly!")
    finally:
        if not args.keep_artifacts:
            print("Cleaning up temporary demonstration artifacts...")
            if os.path.exists(demo_sandbox_dir):
                shutil.rmtree(demo_sandbox_dir, ignore_errors=True)
            for fname in (set(os.listdir("quarantine")) - quarantine_before if os.path.exists("quarantine") else set()):
                try:
                    os.remove(os.path.join("quarantine", fname))
                except OSError:
                    pass
            for fname in (set(os.listdir("reports")) - reports_before if os.path.exists("reports") else set()):
                try:
                    os.remove(os.path.join("reports", fname))
                except OSError:
                    pass
            if os.path.exists(db_path):
                conn = sqlite3.connect(db_path)
                conn.execute("DELETE FROM file_events WHERE id > ?", (max_ids_before["file_events"],))
                conn.execute("DELETE FROM alerts WHERE id > ?", (max_ids_before["alerts"],))
                conn.execute("DELETE FROM incidents WHERE id > ?", (max_ids_before["incidents"],))
                conn.commit()
                conn.close()
            print("Cleanup complete.")


if __name__ == "__main__":
    main()
