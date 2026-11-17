import { spawn, ChildProcess } from 'node:child_process';
import path from 'path';
import fs from 'fs';

export interface DaemonStatusOptions {
  statusFilePath?: string;
  cwd?: string;
}

export function writeDaemonErrorStatus(errorMsg: string, statusFilePath?: string): void {
  try {
    const targetPath = statusFilePath || path.resolve(process.cwd(), 'data', 'monitor_status.json');
    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
    const statusData = {
      is_monitoring: false,
      observer_alive: false,
      pid: null,
      started_at: new Date().toISOString(),
      last_heartbeat: new Date().toISOString(),
      watched_path: path.resolve(process.cwd(), 'data', 'sandbox'),
      last_event_at: null,
      last_error: errorMsg,
      backend_engine: "Unavailable"
    };
    fs.writeFileSync(targetPath, JSON.stringify(statusData, null, 2));
  } catch (ex) {
    console.error('[Server] Failed writing daemon error status:', ex);
  }
}

export interface DaemonProcessState {
  child: ChildProcess | null;
  exited: boolean;
}

export function startDaemonProcess(
  currentState: DaemonProcessState,
  options: {
    pythonCmd: string;
    daemonScript?: string;
    args?: string[];
    cwd?: string;
    statusFilePath?: string;
    isShuttingDown?: () => boolean;
  }
): DaemonProcessState {
  if (currentState.child && !currentState.exited) {
    console.log('[Express Server] Watchdog daemon is already running. Skipping duplicate spawn.');
    return currentState;
  }

  const pythonCmd = options.pythonCmd;
  const spawnArgs = options.args || [options.daemonScript || 'rdrs_daemon.py'];
  const workDir = options.cwd || process.cwd();

  const state: DaemonProcessState = {
    child: null,
    exited: false
  };

  try {
    const child = spawn(pythonCmd, spawnArgs, { cwd: workDir });
    state.child = child;

    child.on('error', (err: any) => {
      console.error(`[RDRS Watchdog Daemon Spawn Error (${pythonCmd})]:`, err.message);
      state.exited = true;
      state.child = null;
      writeDaemonErrorStatus(`Daemon spawn failed (${pythonCmd}): ${err.message}`, options.statusFilePath);
    });

    child.stdout?.on('data', (data) => {
      console.log(`[RDRS Watchdog Daemon] ${data.toString().trim()}`);
    });

    child.stderr?.on('data', (data) => {
      console.error(`[RDRS Watchdog Daemon Error] ${data.toString().trim()}`);
    });

    child.on('exit', (code, signal) => {
      console.log(`[RDRS Watchdog Daemon] Process exited with code ${code}, signal ${signal}`);
      state.exited = true;
      state.child = null;
      if (!options.isShuttingDown?.()) {
        writeDaemonErrorStatus(`Daemon exited unexpectedly with code ${code}, signal ${signal}`, options.statusFilePath);
      }
    });

    return state;
  } catch (err: any) {
    console.error('[RDRS Watchdog Daemon Spawn Failure]', err.message);
    state.exited = true;
    state.child = null;
    writeDaemonErrorStatus(`Daemon spawn exception (${pythonCmd}): ${err.message}`, options.statusFilePath);
    return state;
  }
}

export function waitForChildExit(
  child: ChildProcess,
  termTimeoutMs = 4000,
  killTimeoutMs = 2000
): Promise<boolean> {
  return new Promise((resolve) => {
    let termTimer: NodeJS.Timeout | null = null;
    let killTimer: NodeJS.Timeout | null = null;

    const cleanup = () => {
      if (termTimer) clearTimeout(termTimer);
      if (killTimer) clearTimeout(killTimer);
      child.removeListener('exit', onExit);
    };

    const onExit = () => {
      cleanup();
      resolve(true);
    };

    child.once('exit', onExit);

    // Send SIGTERM first
    try {
      const sent = child.kill('SIGTERM');
      if (!sent) {
        console.warn('[Express Server] child.kill("SIGTERM") returned false');
      }
    } catch (err: any) {
      console.error('[Express Server] Exception sending SIGTERM:', err.message);
    }

    // Wait up to termTimeoutMs for SIGTERM exit
    termTimer = setTimeout(() => {
      console.warn(`[Express Server] Daemon did not exit within ${termTimeoutMs}ms of SIGTERM. Escalating to SIGKILL...`);
      try {
        const sent = child.kill('SIGKILL');
        if (!sent) {
          console.warn('[Express Server] child.kill("SIGKILL") returned false');
        }
      } catch (err: any) {
        console.error('[Express Server] Exception sending SIGKILL:', err.message);
      }

      // Wait up to killTimeoutMs for SIGKILL exit
      killTimer = setTimeout(() => {
        cleanup();
        console.error('[Express Server] Daemon process failed to exit even after SIGKILL escalation.');
        resolve(false);
      }, killTimeoutMs);
    }, termTimeoutMs);
  });
}

export async function closeHttpServer(
  server: any,
  sockets: Set<any>,
  timeoutMs = 3000
): Promise<boolean> {
  if (!server) return true;

  if (typeof server.closeIdleConnections === 'function') {
    try { server.closeIdleConnections(); } catch (e) {}
  }
  if (typeof server.closeAllConnections === 'function') {
    try { server.closeAllConnections(); } catch (e) {}
  }

  for (const socket of sockets) {
    try { socket.destroy(); } catch (e) {}
  }
  sockets.clear();

  return new Promise<boolean>((resolve) => {
    let timer: NodeJS.Timeout | null = null;
    let closed = false;

    const done = (success: boolean) => {
      if (!closed) {
        closed = true;
        if (timer) clearTimeout(timer);
        resolve(success);
      }
    };

    timer = setTimeout(() => {
      console.warn(`[Express Server] HTTP server close timed out after ${timeoutMs}ms.`);
      done(false);
    }, timeoutMs);

    try {
      server.close((err?: Error) => {
        if (err) {
          console.error('[Express Server] Error closing HTTP server:', err);
          done(false);
        } else {
          console.log('[Express Server] HTTP server closed successfully.');
          done(true);
        }
      });
    } catch (ex: any) {
      console.error('[Express Server] Exception during server.close():', ex);
      done(false);
    }
  });
}

export interface ShutdownOptions {
  daemonState: DaemonProcessState;
  httpServer: any;
  activeSockets: Set<any>;
  isShuttingDownFlag: { value: boolean };
  termTimeoutMs?: number;
  killTimeoutMs?: number;
  httpTimeoutMs?: number;
  exitProcess?: boolean;
  onExit?: (code: number) => void;
}

export interface ShutdownResult {
  skippedDuplicate: boolean;
  daemonExitedCleanly: boolean;
  httpClosedCleanly: boolean;
  exitCode: number;
}

export async function executeShutdownSequence(
  options: ShutdownOptions
): Promise<ShutdownResult> {
  if (options.isShuttingDownFlag.value) {
    console.log('[Express Server] Shutdown sequence already in progress. Ignoring duplicate signal.');
    return {
      skippedDuplicate: true,
      daemonExitedCleanly: true,
      httpClosedCleanly: true,
      exitCode: 0
    };
  }
  options.isShuttingDownFlag.value = true;

  console.log('[Express Server] Initiating graceful shutdown sequence...');

  // Close HTTP server and terminate daemon process concurrently / independently
  const httpPromise = closeHttpServer(
    options.httpServer,
    options.activeSockets,
    options.httpTimeoutMs ?? 3000
  );

  let daemonExitedCleanly = true;
  if (options.daemonState.child && !options.daemonState.exited) {
    console.log('[Express Server] Initiating Watchdog daemon process termination...');
    daemonExitedCleanly = await waitForChildExit(
      options.daemonState.child,
      options.termTimeoutMs ?? 4000,
      options.killTimeoutMs ?? 2000
    );
  }

  const httpClosedCleanly = await httpPromise;

  /**
   * FAILURE POLICY FOR NODE SERVER WHEN DAEMON REMAINS ALIVE:
   * 
   * 1. If daemon process termination is confirmed (daemonExitedCleanly === true),
   *    log clean completion and exit process with status code 0 (success).
   * 
   * 2. If daemon process fails to terminate within SIGTERM (4s) and SIGKILL (2s) timeouts
   *    (daemonExitedCleanly === false), the Node server MUST NOT log a successful shutdown
   *    or exit with code 0. Instead, it logs an explicit CRITICAL error and exits with code 1.
   *    Exiting with code 1 signals to container runtime / process managers (systemd, Docker, K8s)
   *    that daemon termination failed, triggering appropriate container force-kill or restart policies.
   */
  const exitCode = daemonExitedCleanly ? 0 : 1;

  if (!daemonExitedCleanly) {
    console.error(
      `[Express Server] CRITICAL SHUTDOWN FAILURE: Watchdog daemon process (PID: ${options.daemonState.child?.pid ?? 'unknown'}) ` +
      `refused to exit even after SIGKILL escalation. Exiting Node server with code 1.`
    );
  } else {
    console.log('[Express Server] Clean shutdown sequence finished successfully.');
  }

  if (options.exitProcess !== false) {
    if (options.onExit) {
      options.onExit(exitCode);
    } else {
      process.exit(exitCode);
    }
  }

  return {
    skippedDuplicate: false,
    daemonExitedCleanly,
    httpClosedCleanly,
    exitCode
  };
}
