# Ransomware Detection & Response System (RDRS)

RDRS is a defensive cybersecurity monitoring, detection, simulation, and incident-response application built around a constrained sandbox. It monitors `./data/sandbox`, calculates Shannon entropy for file data, evaluates file and process signals over a sliding time window, assigns a weighted Threat Score (`0–100`), stores events and incident records in SQLite, copies evidence to `./quarantine`, generates CSV/JSON/HTML incident reports in `./reports`, and streams telemetry to a React SOC dashboard through Express Server-Sent Events (SSE).

> **Safety notice:** RDRS is configured for simulation and demonstration. Run the simulator only against the project's sandbox. Quarantine is evidence-copy behavior: it does not delete the original sandbox files, and the simulation does not terminate operating-system processes. This is a learning/demo tool, not a replacement for an enterprise EDR or incident-response platform.

---

## Contents

- [Architecture](#architecture)
- [Technology stack](#technology-stack)
- [Detection methodology](#detection-methodology)
- [Safety boundaries](#safety-boundaries)
- [Windows 11 setup](#windows-11-setup-powershell)
- [Run the application](#run-the-application)
- [Sandbox simulator](#sandbox-simulator)
- [REST API](#rest-api)
- [Automated tests](#automated-tests)
- [Reports, database, and evidence locations](#reports-database-and-evidence-locations)
- [Docker](#docker)
- [Known limitations and implementation notes](#known-limitations-and-implementation-notes)
- [Troubleshooting](#troubleshooting)
- [Demonstration checklist](#demonstration-checklist)
- [Data flow (viva guide)](#data-flow-viva-guide)

## Architecture

```text
                       config.yaml
                            |
                            v
+--------------------+  +---------------------------+  +-------------------+
| Persistent Python  |->| Python Detection Engine   |<-| Process telemetry |
| Daemon              |  | - Shannon file entropy    |  | (psutil / system) |
| rdrs_daemon.py      |  | - Sliding-window scoring  |  +-------------------+
| Watchdog / fallback |  | - Threat Score 0–100      |
+--------------------+  +-------------+-------------+
                                      |
                       +--------------+--------------+
                       |                             |
                       v                             v
              +----------------+            +------------------+
              | SQLite         |            | Quarantine       |
              | data/rdrs.db   |            | Evidence copies  |
              +----------------+            +------------------+
                       ^                             ^
                       +--------------+--------------+
                                      |
                 +--------------------------------------------+
                 | Express server (server.ts)                 |
                 | Python CLI bridge (src/python_bridge.ts)   |
                 | REST API + SSE (/api/stream)                |
                 +----------------------+---------------------+
                                        |
                                        v
                           +---------------------------+
                           | React + Vite SOC dashboard|
                           | Recharts / Tailwind CSS   |
                           +---------------------------+
```

### Core components

- **Frontend (`src/App.tsx`):** SOC dashboard, threat score history, alerts, file-event log, incident status view, report exports, sandbox simulator, entropy calculator, REST API tester, and test-suite view.
- **Express server (`server.ts`):** Serves the Vite app in development or the built frontend in production. Starts and supervises the Python daemon, exposes REST endpoints, and publishes live updates over SSE.
- **Python bridge (`src/python_bridge.ts`, `rdrs_api_cli.py`):** Runs allowlisted Python actions using argument arrays and `shell: false`, with timeout and output-size controls.
- **Monitoring daemon (`rdrs_daemon.py`, `rdrs/app/detectors/file_monitor.py`):** Monitors only the configured sandbox path, records filesystem events, and sends event information to the detection engine. A polling fallback is available when the Watchdog package is unavailable.
- **Detection engine (`rdrs/app/detectors/detection_engine.py`):** Evaluates recent file and process signals, calculates a score, persists alerts/incidents, and copies validated evidence into quarantine.
- **Database (`rdrs/app/database/db.py`):** SQLite storage for file events, process information, alerts, and incidents.
- **Report generator (`rdrs/app/reports/report_generator.py`):** Produces incident JSON, CSV summary, and HTML report files.

## Technology stack

- **Frontend:** React, TypeScript, Vite, Tailwind CSS, Recharts, Lucide React.
- **Web/API tier:** Node.js, Express, `tsx`, `esbuild`, Server-Sent Events.
- **Detection core:** Python, Watchdog, psutil, PyYAML, Pydantic, Loguru, SQLite.
- **Testing:** Python `unittest` (and pytest-related tooling where installed), Node.js tests through `tsx`.
- **Packaging:** npm (or Bun, if you choose to use that package manager consistently), Docker and Docker Compose files.

## Detection methodology

### Shannon entropy

Shannon entropy estimates the randomness of file bytes. RDRS samples up to 64 KB per file for this calculation. Typical values depend on file type and content; the configured high-entropy threshold is `7.2` bits per byte.

- Plain text and source code commonly have lower entropy.
- Compressed and binary files can have higher entropy.
- Encrypted or random-like data can approach `8.0` bits per byte.

Entropy alone is not treated as proof of ransomware. In the live sandbox check, the entropy-only simulation reported `25/100` and remained **Normal**, with no alert.

### Weighted threat signals

The engine evaluates signals within the configured sliding window (`time_window_seconds`, 60 seconds by default). The weights documented by the project are:

| Signal | Trigger condition | Weight |
|---|---|---:|
| Rapid encryption-like activity | At least 15 qualifying file modifications in the window | 40 |
| Mass file renaming | At least 8 qualifying rename events or `.locked` targets in the window | 30 |
| High file entropy | At least one file with entropy `>= 7.2` bits/byte | 25 |
| CPU spike | CPU signal `>= 75%` | 15 |
| Suspicious process metadata | `process_info.is_suspicious == true` | 10 |

The final score is capped at `100`.

| Severity | Score | Meaning |
|---|---:|---|
| Normal | 0–39 | No alert is generated |
| Warning | 40–69 | Warning alert and evidence-copy response |
| Critical | 70–100 | Critical alert, incident record, evidence copies, and incident reports |

The scoring policy helps avoid treating one high-entropy file as a ransomware incident. Newly created files that are modified during the same analysis window are excluded from the pre-existing-file modification count, reducing false positives from ordinary file creation workflows.

## Safety boundaries

- **Simulation mode:** `system.simulation_mode` should remain `true` for the demonstration configuration.
- **Monitoring scope:** `monitoring.watch_paths` should point only to `./data/sandbox`.
- **Evidence-copy behavior:** Quarantine copies evidence using file-copy behavior; it does not delete or move the original sandbox file.
- **Path validation:** Quarantine logic validates candidate paths against configured sandbox roots and rejects paths outside those roots, including traversal and escaping symlink cases.
- **Process safety:** The simulation supplies process metadata for scoring; it does not terminate real operating-system processes.
- **Bridge safety:** The Python bridge uses an action allowlist, argument arrays, `shell: false`, timeouts, and bounded output handling.
- **Report output:** Reports are written under `./reports/`; the report generator sanitizes filenames and escapes HTML content.

Do not change the monitored path to a personal, system, or otherwise important directory for a demonstration.

## Windows 11 setup (PowerShell)

Open PowerShell in the project root (the folder containing `package.json`, `server.ts`, and `requirements.txt`).

### 1. Create and activate the Python environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation for the current terminal session, run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
```

### 2. Install Python dependencies

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Install Node dependencies

```powershell
npm install
```

Use one package manager consistently for a given install rather than switching back and forth between npm and Bun lockfiles.

### 4. Optional: select the virtual-environment Python executable explicitly

When needed, set `PYTHON_PATH` so the Node server uses the project's virtual environment:

```powershell
$env:PYTHON_PATH = (Resolve-Path .\.venv\Scripts\python.exe).Path
```

## Run the application

From the project root, start the development server:

```powershell
$env:PORT = "3001"  # Optional: use this when port 3000 is already occupied
npm run dev
```

The application defaults to port `3000` when `PORT` is not set. Open the matching local URL in your browser:

- `http://localhost:3000` (default)
- `http://localhost:3001` (when started with `PORT=3001`)

The Express server starts the Python monitoring daemon automatically. **Do not start `rdrs_daemon.py` separately while the Node server is running.**

To stop the application, press `Ctrl+C` in the terminal running `npm run dev`. The server's shutdown handler manages the daemon shutdown sequence.

## Sandbox simulator

The simulator operates only in `./data/sandbox`. The current interface provides buttons for creating normal files, running an entropy spike, mass file renaming, and resetting the sandbox/database. The `full_simulation` mode is available through the API request below.

### Observed scenario behavior

The following outcomes were observed during the project's live Windows demonstration:

| Scenario | Observed result | Expected handling |
|---|---|---|
| Create normal files | 5 plain-text files; dashboard remained Normal with score 0 | Ordinary activity; no alert |
| Entropy spike | Simulator reported `25/100`; mean entropy was about `7.91` bits/byte | Normal; no alert from entropy alone |
| Mass file renaming | 10 `.docx` files were physically renamed to `.docx.locked`; simulator reported `30/100` | Normal; no alert from renaming alone |
| Full simulation | API reported `90/100`, Critical; 1 active alert and 1 incident were created | Critical alert, incident, 15 affected files, quarantine evidence copies, and reports |
| Reset | Dashboard returned to Normal with 0 events, 0 alerts, score 0, and entropy 0 | Clears the sandbox and SQLite test state |

The simulator's low-risk score is shown in its response message. The dashboard's persisted Threat Score remains `0` when no alert has been created; after a Critical alert is persisted, the dashboard displays the alert score.

### Run the Full Simulation through PowerShell

The UI's entropy-spike button runs the entropy-only scenario; it is not the combined Critical scenario. To run the combined `full_simulation`, use a second PowerShell terminal while the RDRS server is running:

```powershell
$body = @{ attackType = "full_simulation" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:3001/api/simulator/run" `
  -Method POST `
  -ContentType "application/json" `
  -Body $body | ConvertTo-Json -Depth 8
```

If the server is running on the default port, replace `3001` with `3000`.

The demonstrated full-simulation response was:

- Threat score: `90/100`
- Threat level: `Critical`
- Active alerts: `1`
- Simulator event count in the response: `15`
- Mean entropy: `7.91` bits/byte
- Incident: `INC-20261116-0030`
- Affected files: `15`

#### Latest live verification — 19 November 2026

After deploying commit `87cf8f9`, the full ransomware simulation was
successfully tested on the live Render deployment.

- API status: `success`
- Threat score: `90/100`
- Threat level: `Critical`
- Active alerts: `1`
- Simulator event count: `15`
- Mean entropy: `7.91` bits/byte
- Incident ID: `INC-20261119-0001`
- Affected files: `15`
- Daemon monitoring: `Healthy`

The dashboard confirmed exactly one Critical alert and one incident,
with the incident status `Contained (Simulation)`.

The duplicate daemon alert was not reproduced during this verification.

The dashboard's SQLite event count can be higher than the simulator's event count because the Watchdog daemon also records filesystem activity generated during the simulation.

### Reset after testing

Use **Sandbox Simulator → Reset Sandbox & DB** and wait for the success message. The reset demonstration cleared sandbox contents and SQLite event/alert state. It did **not** remove historical files from `./quarantine/` or generated files from `./reports/`; inspect and clean those folders manually only when you intentionally want to remove retained evidence and reports.

## REST API

The API is served by the local Express server. Replace the port below if your `PORT` environment variable is different.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Checks daemon and database health. |
| `GET` | `/api/status` | Returns threat level/score, alert and event counts, daemon state, simulation mode, CPU usage, and mean entropy. |
| `GET` | `/api/alerts?severity=` | Lists alerts, optionally filtered by severity. |
| `POST` | `/api/alerts/update` | Updates alert status using `{ "alertId": 1, "status": "Acknowledged" }`. |
| `GET` | `/api/events?type=&search=` | Queries file events by type and path substring. |
| `GET` | `/api/incidents` | Returns incident information or the clean baseline state. |
| `POST` | `/api/incidents/update` | Updates incident status using `{ "incidentId": "INC-...", "status": "Resolved" }`. |
| `GET` | `/api/history` | Returns threat-score history. |
| `POST` | `/api/entropy/calculate` | Calculates entropy from `{ "text": "sample text" }`. |
| `POST` | `/api/simulator/run` | Runs a sandbox action using `{ "attackType": "..." }`. |
| `GET` | `/api/tests/run` | Runs the Python test suite through the bridge. |
| `GET` | `/api/stream` | SSE stream of status, alerts, events, incident, and history. |

Supported simulator `attackType` values documented by the application: `create_normal`, `entropy_spike`, `full_simulation`, `mass_rename`, and `reset`.

Example request body for the combined Critical simulation:

```json
{
  "attackType": "full_simulation"
}
```

## Automated tests

Run the Python test suite from the project root with the virtual environment activated:

```powershell
$env:PYTHONPATH = ".;tests"
python -m unittest discover -s tests -v
```

If the Node test files are present in your checkout, run:

```powershell
npx tsx --test tests/test_node_lifecycle.ts tests/test_python_bridge.ts
```

The Python tests use isolated temporary paths/mocks for their test data so normal test runs should not require using the live sandbox database. On Windows, filesystem capabilities such as symlink creation may cause an individual security test to be skipped when the environment does not permit symlinks.

## Reports, database, and evidence locations

| Path | Purpose |
|---|---|
| `./data/rdrs.db` | SQLite database (WAL mode) containing events, alerts, and incidents. |
| `./data/sandbox/` | The only directory monitored by the demonstration configuration. |
| `./quarantine/` | Evidence copies created by the response workflow. |
| `./reports/` | Generated incident reports. |
| `./logs/rdrs_audit.log` | Audit/runtime log output. |
| `./data/rdrs_daemon.lock` | Single-instance daemon lock. |
| `./data/monitor_status.json` | Daemon heartbeat/status file. |

For a Critical incident, the report generator creates:

- `incident_<INCIDENT_ID>.json` — machine-readable incident record.
- `incident_<INCIDENT_ID>.html` — human-readable incident report.
- `incidents_summary_YYYYMMDD.csv` — tabular incident summary.

The live demonstration generated all three formats for `INC-20261116-0030`, and their incident ID, score (`90`), severity (`Critical`), and affected-file count (`15`) matched.

## Docker

The repository includes Docker packaging files. The deployment command is:

```bash
docker compose up -d --build
```

Docker deployment was not part of the Windows live verification described above. Verify the compose setup on a host with Docker Engine installed before relying on it for deployment. Keep simulation mode enabled and retain the sandbox-only watch path.

## Known limitations and implementation notes

- **Simulation-only containment:** RDRS copies evidence to quarantine and labels the incident `Contained (Simulation)`. It does not terminate processes or perform real endpoint isolation.
- **Entropy-only signal:** One high-entropy file or the entropy-only simulator does not independently reach the Warning threshold. The observed entropy-only scenario scored `25/100` and generated no alert.
- **Mass-renaming signal:** The observed mass-renaming scenario scored `30/100` and generated no alert by itself.
- **Critical demo path:** The combined `full_simulation` is invoked through `POST /api/simulator/run` with `attackType` set to `full_simulation`; the current simulator UI does not expose this as a separate button.
- **Polling fallback:** Without the Watchdog dependency, the application can use a polling fallback. Polling may observe filesystem changes differently and with greater latency than native Watchdog events.
- **Quarantine and reports persist across reset:** The simulator reset clears sandbox/database test state, but historical quarantine evidence and report files remain in their respective folders.
- **JSON report field:** In the JSON report inspected during the live demonstration, `incident.quarantine_paths` was serialized as a string containing JSON array text rather than as a native JSON array. Consumers that need the individual paths should parse that string; this representation could be improved in a future change.
- **Port conflicts:** The server defaults to port `3000`. Set `PORT` to another free port (for example, `3001`) when the default is already in use.

## Troubleshooting

- **Port 3000 is already in use:** Start with `$env:PORT = "3001"` in PowerShell, then run `npm run dev` and open `http://localhost:3001`.
- **Python bridge cannot find the interpreter:** Activate `.venv` before starting the server, or set `PYTHON_PATH` to `.venv\Scripts\python.exe`.
- **PowerShell blocks virtual-environment activation:** Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned` in that terminal, then activate `.venv` again.
- **Daemon reports unhealthy:** Check the terminal output and `./logs/rdrs_audit.log`. Ensure the Node server is the only process managing the daemon; do not launch a second daemon manually.
- **Dashboard does not update:** Check that the left status panel reports the SSE stream as active and that the server terminal remains running.
- **Vite config warning:** A Vite config-loader warning can appear during startup while the Express/Vite server still starts. Confirm the final server-running message and test the local page before treating the warning as a startup failure.

## Demonstration checklist

1. **Show safe configuration.** Open `config.yaml` and confirm simulation mode is enabled and the monitored path is only `./data/sandbox`.
2. **Start the server.** Activate `.venv`, set `PORT` if needed, and run `npm run dev`. Confirm the daemon starts and the server prints its local URL.
3. **Show the clean dashboard.** Confirm Normal, score `0`, no active alerts, and an active SSE stream.
4. **Create normal files.** Use **Sandbox Simulator → Create Normal Files**. Show low-entropy file events and no alert.
5. **Run entropy-only simulation.** Use **Entropy Spike (.locked)**. Explain that high entropy alone scored `25/100` in the live test and remained Normal.
6. **Run mass renaming.** Use **Mass File Renaming**. Confirm the files receive the `.locked` extension in `./data/sandbox`; the live test scored `30/100` and remained Normal.
7. **Reset to a clean state.** Use **Reset Sandbox & DB** and wait for its success message.
8. **Run the combined Critical simulation.** Use the PowerShell API command in [Sandbox simulator](#sandbox-simulator) with `attackType = "full_simulation"`.
9. **Verify the response.** Show Critical score `90`, one active alert, and the Critical dashboard state.
10. **Inspect the alert and incident.** Open **Alerts** and **Incidents**. Show the four detection signals and the 15 affected `.locked` files.
11. **Inspect evidence and reports.** Show the newest 15 quarantine copies and the CSV, JSON, and HTML reports in `./reports/`.
12. **Reset the sandbox/database.** Return the live dashboard to Normal. Explain that quarantine evidence and generated reports remain until manually cleaned up.

## Data flow (viva guide)

1. **Filesystem capture:** `rdrs_daemon.py` owns the daemon lock and monitors the configured sandbox directory using Watchdog or its polling fallback. The event handler observes file create, modify, rename, and delete operations and calculates file entropy.
2. **Persistence and scoring:** Events are stored in SQLite. Recent qualifying events are evaluated within the configured sliding window. The five weighted signals are combined and capped at `100`; entropy by itself contributes `25` and remains Normal.
3. **Alert and incident response:** Warning/Critical detections create alerts. Critical detections also create an incident record. Candidate evidence paths are validated against the sandbox before copies are written to `./quarantine/`; originals are preserved.
4. **Report generation:** Critical incident data is exported to JSON, CSV, and HTML files under `./reports/`.
5. **API and dashboard:** `server.ts` supervises the daemon and exposes REST endpoints. The Python bridge invokes allowlisted CLI actions. The React dashboard receives status, alert, event, incident, and history updates through `/api/stream`.
