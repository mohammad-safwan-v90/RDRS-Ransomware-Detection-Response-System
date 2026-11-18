import { execFile, spawn } from 'node:child_process';
import path from 'node:path';

export const ALLOWED_ACTIONS = [
  'dashboard',
  'health',
  'status',
  'alerts',
  'update_alert',
  'events',
  'incidents',
  'update_incident',
  'entropy',
  'simulator',
  'run_tests',
  'history'
] as const;

export type BridgeAction = (typeof ALLOWED_ACTIONS)[number];

export const DEFAULT_TIMEOUT_MS = 10000;
export const DEFAULT_MAX_STDOUT_BYTES = 1024 * 1024; // 1 MiB
export const DEFAULT_MAX_STDERR_BYTES = 256 * 1024;  // 256 KiB

export interface PythonBridgeOptions {
  pythonCmd?: string;
  scriptPath?: string;
  cwd?: string;
  timeoutMs?: number;
  maxStdoutBytes?: number;
  maxStderrBytes?: number;
  env?: NodeJS.ProcessEnv;
}

export function getDefaultPythonCmd(): string {
  return process.env.PYTHON_PATH || (process.platform === 'win32' ? 'python' : 'python3');
}

function resolvePositiveLimit(value: number | undefined, fallback: number): number | null {
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) {
    return null;
  }
  return value;
}

export async function callPythonBridge(
  action: string,
  args: string[] = [],
  options: PythonBridgeOptions = {}
): Promise<any> {
  if (!ALLOWED_ACTIONS.includes(action as BridgeAction)) {
    return { error: 'Action not allowed', action };
  }

  const timeoutMs = resolvePositiveLimit(options.timeoutMs, DEFAULT_TIMEOUT_MS);
  const maxStdoutBytes = resolvePositiveLimit(options.maxStdoutBytes, DEFAULT_MAX_STDOUT_BYTES);
  const maxStderrBytes = resolvePositiveLimit(options.maxStderrBytes, DEFAULT_MAX_STDERR_BYTES);

  if (timeoutMs === null || maxStdoutBytes === null || maxStderrBytes === null) {
    return {
      error: 'Invalid bridge configuration',
      details: 'timeoutMs, maxStdoutBytes, and maxStderrBytes must be positive integers (>= 1)'
    };
  }

  const pythonCmd = options.pythonCmd ?? getDefaultPythonCmd();
  const cwd = options.cwd ?? process.cwd();
  const scriptPath = options.scriptPath ?? path.resolve(cwd, 'rdrs_api_cli.py');

  return new Promise((resolve) => {
    const safeArgs = args.map((a) => (a === undefined || a === null ? '' : String(a)));
    const spawnArgs = [scriptPath, action, ...safeArgs];
    const child = spawn(pythonCmd, spawnArgs, {
      cwd,
      shell: false,
      env: {
        ...process.env,
        ...(options.env || {}),
        PYTHONPATH: options.env?.PYTHONPATH ?? cwd
      }
    });

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let settled = false;
    let timeoutTimer: ReturnType<typeof setTimeout> | undefined;
    let killEscalationTimer: ReturnType<typeof setTimeout> | undefined;

    const terminateChildSafely = () => {
      try {
        child.stdout?.destroy();
      } catch {
        // ignore stream destroy errors
      }
      try {
        child.stderr?.destroy();
      } catch {
        // ignore stream destroy errors
      }

      if (child.exitCode !== null || child.signalCode !== null) {
        return;
      }

      try {
        child.kill('SIGTERM');
      } catch {
        return;
      }

      killEscalationTimer = setTimeout(() => {
        killEscalationTimer = undefined;
        if (child.exitCode === null && child.signalCode === null) {
          if (process.platform === 'win32' && child.pid) {
            try {
              execFile('taskkill', ['/PID', String(child.pid), '/T', '/F'], () => {
                // ignore taskkill callback errors if process already exited
              });
            } catch {
              // fallback to child.kill below
            }
          }
          try {
            child.kill('SIGKILL');
          } catch {
            // ignore if already exited
          }
        }
      }, 250);
      killEscalationTimer.unref?.();

      child.once('exit', () => {
        if (killEscalationTimer) {
          clearTimeout(killEscalationTimer);
          killEscalationTimer = undefined;
        }
      });
    };

    const cleanup = () => {
      if (timeoutTimer) {
        clearTimeout(timeoutTimer);
        timeoutTimer = undefined;
      }
      child.stdout?.off('data', onStdoutData);
      child.stderr?.off('data', onStderrData);
      child.off('close', onClose);
      child.off('error', onError);
    };

        const finish = async (result: any, terminateChild = false) => {
      if (settled) return;
      settled = true;
      cleanup();

      if (terminateChild) {
        const waitForClose = new Promise<void>((resolveClose) => {
          const closeTimeout = setTimeout(() => {
            child.off('close', onChildClose);
            resolveClose();
          }, 5000);

          const onChildClose = () => {
            clearTimeout(closeTimeout);
            resolveClose();
          };

          child.once('close', onChildClose);
        });

        terminateChildSafely();
        await waitForClose;
      }

      resolve(result);
    };

    const onStdoutData = (chunk: Buffer | string) => {
      if (settled) return;
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      if (stdoutBytes + buf.length > maxStdoutBytes) {
        console.error(
          `Python Bridge Stdout Limit (${action}): exceeded ${maxStdoutBytes} bytes (chunk ${buf.length} bytes)`
        );
        finish(
          {
            error: 'Output limit exceeded',
            stream: 'stdout',
            maxBytes: maxStdoutBytes,
            details: `Python stdout exceeded maximum allowed size of ${maxStdoutBytes} bytes`
          },
          true
        );
        return;
      }
      stdoutBytes += buf.length;
      stdoutChunks.push(buf);
    };

    const onStderrData = (chunk: Buffer | string) => {
      if (settled) return;
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      if (stderrBytes + buf.length > maxStderrBytes) {
        console.error(
          `Python Bridge Stderr Limit (${action}): exceeded ${maxStderrBytes} bytes (chunk ${buf.length} bytes)`
        );
        finish(
          {
            error: 'Stderr limit exceeded',
            stream: 'stderr',
            maxBytes: maxStderrBytes,
            details: `Python stderr exceeded maximum allowed size of ${maxStderrBytes} bytes`
          },
          true
        );
        return;
      }
      stderrBytes += buf.length;
      stderrChunks.push(buf);
    };

    const onClose = (code: number | null) => {
      if (settled) return;
      const stdoutData = Buffer.concat(stdoutChunks, stdoutBytes).toString('utf8');
      const stderrData = Buffer.concat(stderrChunks, stderrBytes).toString('utf8');

      if (code !== 0) {
        console.error(`Python Bridge Error (${action}) code ${code}:`, stderrData);
        finish({ error: 'Python execution failed', details: stderrData, code });
        return;
      }

      try {
        const trimmed = stdoutData.trim();
        const jsonStart = trimmed.indexOf('{');
        const jsonEnd = trimmed.lastIndexOf('}');
        if (jsonStart !== -1 && jsonEnd !== -1 && jsonEnd >= jsonStart) {
          finish(JSON.parse(trimmed.substring(jsonStart, jsonEnd + 1)));
        } else {
          finish(JSON.parse(trimmed));
        }
      } catch (error: any) {
        console.error(`Python Bridge Parse Error (${action}):`, error, stdoutData);
        finish({ error: 'JSON parse failed', details: error.message, raw: stdoutData });
      }
    };

    const onError = (err: Error) => {
      if (settled) return;
      console.error(`Python Bridge Spawn Error (${action}):`, err);
      finish({ error: 'Spawn failed', details: err.message });
    };

    timeoutTimer = setTimeout(() => {
      console.error(`Python Bridge Timeout (${action}) after ${timeoutMs}ms`);
      finish(
        { error: 'Python execution timed out', details: `Process killed after ${timeoutMs}ms` },
        true
      );
    }, timeoutMs);

    child.stdout?.on('data', onStdoutData);
    child.stderr?.on('data', onStderrData);
    child.on('close', onClose);
    child.on('error', onError);
  });
}
