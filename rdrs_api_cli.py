"""
RDRS Python CLI Bridge - Called by Node.js to return 100% real Python SQLite and detection data.
"""

import sys
import json
import os
import unittest

sys.path.insert(0, os.path.abspath("."))

from rdrs.app.api.main import (
    get_real_health,
    get_real_system_status,
    get_real_alerts,
    update_alert_status,
    get_real_events,
    get_real_incidents,
    update_incident_status,
    run_sandbox_simulation,
    get_real_threat_history,
)
from rdrs.app.core.entropy import calculate_shannon_entropy
from rdrs.app.core.logging_config import logger

ALLOWED_ALERT_STATUSES = {"Unacknowledged", "Acknowledged", "Resolved"}
ALLOWED_INCIDENT_STATUSES = {"Contained (Simulation)", "Under Investigation", "Resolved", "Normal Operation"}
ALLOWED_SIMULATIONS = {"create_normal", "entropy_spike", "full_simulation", "mass_rename", "reset"}


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No action specified"}))
        return

    action = sys.argv[1]

    try:
        if action == "health":
            print(json.dumps(get_real_health()))

        elif action == "status":
            print(json.dumps(get_real_system_status()))

        elif action == "alerts":
            sev = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] not in ("undefined", "") else None
            print(json.dumps({"alerts": get_real_alerts(severity_filter=sev)}))

        elif action == "update_alert":
            if len(sys.argv) < 4:
                print(json.dumps({"error": "Missing alert_id or status", "status_code": 400}))
                return
            try:
                alert_id = int(sys.argv[2])
            except ValueError:
                print(json.dumps({"error": f"Invalid alert_id: {sys.argv[2]}", "status_code": 400}))
                return
            new_status = sys.argv[3]
            if new_status not in ALLOWED_ALERT_STATUSES:
                print(json.dumps({"error": f"Invalid alert status: {new_status}", "status_code": 400}))
                return
            print(json.dumps(update_alert_status(alert_id, new_status)))

        elif action == "events":
            evt_type = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] not in ("undefined", "") else None
            search_txt = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] not in ("undefined", "") else None
            print(json.dumps({"events": get_real_events(event_type_filter=evt_type, search=search_txt)}))

        elif action == "incidents":
            print(json.dumps({"incident": get_real_incidents()}))

        elif action == "update_incident":
            if len(sys.argv) < 4:
                print(json.dumps({"error": "Missing incident_id or status", "status_code": 400}))
                return
            inc_id = sys.argv[2]
            new_status = sys.argv[3]
            if new_status not in ALLOWED_INCIDENT_STATUSES:
                print(json.dumps({"error": f"Invalid incident status: {new_status}", "status_code": 400}))
                return
            print(json.dumps(update_incident_status(inc_id, new_status)))

        elif action == "history":
            print(json.dumps({"history": get_real_threat_history()}))

        elif action == "entropy":
            text = sys.argv[2] if len(sys.argv) > 2 else ""
            buf = text.encode("utf-8")
            entropy = calculate_shannon_entropy(buf)
            res = {
                "entropy": entropy,
                "length": len(buf),
                "isSuspicious": entropy >= 7.2,
                "classification": "Encrypted / High Randomness" if entropy >= 7.2 else "Binary / Compressed" if entropy >= 6.0 else "Plain Text / Source Code"
            }
            print(json.dumps(res))

        elif action == "simulator":
            attack_type = sys.argv[2] if len(sys.argv) > 2 else "entropy_spike"
            if attack_type not in ALLOWED_SIMULATIONS:
                print(json.dumps({"error": f"Unknown simulation type: {attack_type}", "status_code": 400}))
                return
            res = run_sandbox_simulation(attack_type)
            print(json.dumps(res))

        elif action == "run_tests":
            old_stdout = sys.stdout
            sys.stdout = sys.stderr
            cov = None
            coverage_str = None
            try:
                try:
                    import coverage
                    cov = coverage.Coverage(source=["rdrs"])
                    cov.start()
                except ImportError:
                    cov = None

                loader = unittest.TestLoader()
                suite = loader.discover("tests", pattern="test_*.py")
                with open(os.devnull, "w") as devnull:
                    runner = unittest.TextTestRunner(stream=devnull)
                    result = runner.run(suite)

                if cov is not None:
                    cov.stop()
                    cov.save()
                    try:
                        with open(os.devnull, "w") as cov_devnull:
                            pct = cov.report(file=cov_devnull)
                        coverage_str = f"{pct:.1f}%"
                    except Exception:
                        coverage_str = None

                total = result.testsRun
                failures = len(result.failures) + len(result.errors)
                passed = total - failures
                res = {
                    "tests_run": total,
                    "passed": passed,
                    "failures": failures,
                    "success": result.wasSuccessful(),
                    "coverage": coverage_str,
                    "coverage_available": coverage_str is not None
                }
            finally:
                sys.stdout = old_stdout
            print(json.dumps(res))

        else:
            print(json.dumps({"error": f"Unknown action: {action}", "status_code": 400}))
    except Exception as ex:
        logger.exception(f"CLI bridge unhandled exception for action '{action}': {ex}")
        sys.exit(1)


if __name__ == "__main__":
    main()

