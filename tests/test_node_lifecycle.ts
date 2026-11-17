import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'path';
import fs from 'fs';
import os from 'os';
import http from 'http';
import { EventEmitter } from 'events';
import { spawn, ChildProcess } from 'child_process';
import {
  writeDaemonErrorStatus,
  startDaemonProcess,
  waitForChildExit,
  closeHttpServer,
  executeShutdownSequence,
  DaemonProcessState
} from '../src/server_lifecycle.js';

function createTestEnv() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rdrs_node_iso_'));
  const statusPath = path.join(dir, 'status.json');
  const cleanup = () => {
    try {
      if (fs.existsSync(dir)) {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    } catch (e) {}
  };
  return { dir, statusPath, cleanup };
}

test('1. [Real Child Process] Missing Python executable (ENOENT)', async () => {
  const env = createTestEnv();
  try {
    const initialState: DaemonProcessState = { child: null, exited: true };
    const state = startDaemonProcess(initialState, {
      pythonCmd: 'python_non_existent_cmd_xyz_999',
      statusFilePath: env.statusPath
    });

    assert.ok(state.child !== null, 'Child process reference should be created');
    await new Promise<void>((resolve) => {
      state.child?.on('error', () => {
        setTimeout(resolve, 50);
      });
    });

    assert.equal(state.exited, true, 'state.exited must be true on spawn error');
    assert.equal(state.child, null, 'state.child must be cleared to null on spawn error');

    const statusContent = JSON.parse(fs.readFileSync(env.statusPath, 'utf-8'));
    assert.equal(statusContent.is_monitoring, false);
    assert.equal(statusContent.observer_alive, false);
    assert.match(statusContent.last_error, /Daemon spawn failed/);
  } finally {
    env.cleanup();
  }
});

test('2. [Real Child Process] Permission failure (EACCES)', async (t) => {
  if (process.platform === 'win32') {
    t.skip('POSIX executable permission bits are not enforced for .sh files on Windows');
    return;
  }

  const env = createTestEnv();
  try {
    const unexecutableFile = path.join(env.dir, 'no_exec.sh');
    fs.writeFileSync(unexecutableFile, 'echo "test"', { mode: 0o600 });

    const initialState: DaemonProcessState = { child: null, exited: true };
    const state = startDaemonProcess(initialState, {
      pythonCmd: unexecutableFile,
      statusFilePath: env.statusPath
    });

    assert.ok(state.child !== null, 'Child process reference should be created');
    await new Promise<void>((resolve) => {
      state.child?.on('error', () => {
        setTimeout(resolve, 50);
      });
    });

    assert.equal(state.exited, true, 'state.exited must be true on permission failure');
    assert.equal(state.child, null, 'state.child must be cleared on permission failure');

    const statusContent = JSON.parse(fs.readFileSync(env.statusPath, 'utf-8'));
    assert.equal(statusContent.is_monitoring, false);
    assert.match(statusContent.last_error, /Daemon spawn failed/);
  } finally {
    env.cleanup();
  }
});

test('3. [Real Child Process] Unexpected child exit marks status unavailable', async () => {
  const env = createTestEnv();
  try {
    const initialState: DaemonProcessState = { child: null, exited: true };
    const state = startDaemonProcess(initialState, {
      pythonCmd: process.execPath,
      args: ['-e', 'process.exit(42)'],
      statusFilePath: env.statusPath,
      isShuttingDown: () => false
    });

    assert.ok(state.child !== null);
    await new Promise<void>((resolve) => {
      state.child?.on('exit', () => {
        setTimeout(resolve, 50);
      });
    });

    assert.equal(state.exited, true, 'state.exited must be true after process exit');
    assert.equal(state.child, null, 'state.child must be null after exit');

    const statusContent = JSON.parse(fs.readFileSync(env.statusPath, 'utf-8'));
    assert.equal(statusContent.is_monitoring, false);
    assert.match(statusContent.last_error, /exited unexpectedly with code 42/);
  } finally {
    env.cleanup();
  }
});

test('4. [Real Child Process] Normal shutdown does not write unexpected-exit error', async () => {
  const env = createTestEnv();
  try {
    const initialState: DaemonProcessState = { child: null, exited: true };
    const state = startDaemonProcess(initialState, {
      pythonCmd: process.execPath,
      args: ['-e', 'process.exit(0)'],
      statusFilePath: env.statusPath,
      isShuttingDown: () => true
    });

    await new Promise<void>((resolve) => {
      state.child?.on('exit', () => setTimeout(resolve, 50));
    });

    assert.equal(state.exited, true);
    assert.equal(fs.existsSync(env.statusPath), false, 'Normal shutdown must NOT write unexpected exit status');
  } finally {
    env.cleanup();
  }
});

test('5. [Real Child Process] Normal SIGTERM exit', async () => {
  const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)']);
  try {
    const exitedCleanly = await waitForChildExit(child, 1000, 1000);
    assert.equal(exitedCleanly, true, 'waitForChildExit must return true on SIGTERM exit');
  } finally {
    if (child.exitCode === null && !child.killed) {
      try { child.kill('SIGKILL'); } catch (e) {}
    }
  }
});

test('6. [Real Child Process] SIGTERM ignored, followed by SIGKILL escalation', async () => {
  const child = spawn(process.execPath, ['-e', 'process.on("SIGTERM", () => {}); setInterval(() => {}, 1000)']);
  try {
    const exitedCleanly = await waitForChildExit(child, 300, 500);
    assert.equal(exitedCleanly, true, 'waitForChildExit must return true after SIGKILL escalation');
  } finally {
    if (child.exitCode === null && !child.killed) {
      try { child.kill('SIGKILL'); } catch (e) {}
    }
  }
});

test('7. [Mock Child Process] Child still alive after SIGKILL timeout (Failure Policy Check)', async () => {
  const mockChild = new EventEmitter() as unknown as ChildProcess;
  mockChild.kill = (_signal?: any): boolean => true;

  const exitedCleanly = await waitForChildExit(mockChild, 100, 100);
  assert.equal(exitedCleanly, false, 'waitForChildExit must return false if child fails to exit within SIGKILL timeout');
});

test('8. [Real Server & Sockets] HTTP server with long-lived SSE connection', async () => {
  const activeSockets = new Set<any>();
  const server = http.createServer((req, res) => {
    if (req.url === '/api/stream') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream' });
      res.write('data: hello\n\n');
    }
  });

  server.on('connection', (socket) => {
    activeSockets.add(socket);
    socket.on('close', () => activeSockets.delete(socket));
  });

  try {
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const address = server.address() as any;
    const port = address.port;

    const req = http.get(`http://localhost:${port}/api/stream`);
    await new Promise<void>((resolve) => req.on('response', () => resolve()));

    assert.equal(activeSockets.size, 1, 'Active SSE socket should be tracked');

    const closed = await closeHttpServer(server, activeSockets, 1000);
    assert.equal(closed, true, 'HTTP server must close successfully');
    assert.equal(activeSockets.size, 0, 'Active sockets set must be cleared');
  } finally {
    try { server.close(); } catch (e) {}
  }
});

test('9. [Orchestration] Multiple shutdown signals idempotency & daemon signal count', async () => {
  let sigtermCount = 0;
  const mockDaemon = new EventEmitter() as unknown as ChildProcess;
  mockDaemon.kill = (signal?: any): boolean => {
    if (signal === 'SIGTERM') sigtermCount++;
    setImmediate(() => mockDaemon.emit('exit', 0, 'SIGTERM'));
    return true;
  };

  let httpCloseCount = 0;
  const mockHttpServer = {
    close: (cb: any) => {
      httpCloseCount++;
      setImmediate(cb);
    }
  };

  const daemonState: DaemonProcessState = { child: mockDaemon, exited: false };
  const isShuttingDownFlag = { value: false };
  const activeSockets = new Set();

  const [res1, res2] = await Promise.all([
    executeShutdownSequence({
      daemonState,
      httpServer: mockHttpServer,
      activeSockets,
      isShuttingDownFlag,
      exitProcess: false
    }),
    executeShutdownSequence({
      daemonState,
      httpServer: mockHttpServer,
      activeSockets,
      isShuttingDownFlag,
      exitProcess: false
    })
  ]);

  assert.equal(res1.skippedDuplicate, false, 'First shutdown call must execute');
  assert.equal(res2.skippedDuplicate, true, 'Second concurrent shutdown call must be skipped');
  assert.equal(sigtermCount, 1, 'Daemon must receive exactly ONE SIGTERM');
  assert.equal(httpCloseCount, 1, 'HTTP server close must be called exactly ONCE');
});

test('10. [Orchestration] Shutdown with no daemon child / already exited daemon', async () => {
  const isShuttingDownFlag = { value: false };
  const daemonState: DaemonProcessState = { child: null, exited: true };

  const res = await executeShutdownSequence({
    daemonState,
    httpServer: null,
    activeSockets: new Set(),
    isShuttingDownFlag,
    exitProcess: false
  });

  assert.equal(res.daemonExitedCleanly, true);
  assert.equal(res.httpClosedCleanly, true);
  assert.equal(res.exitCode, 0, 'Exit code must be 0 when daemon is already exited or null');
});

test('11. [Orchestration] Shutdown when daemon refuses to exit triggers exit code 1 failure policy', async () => {
  const mockDaemon = new EventEmitter() as unknown as ChildProcess;
  (mockDaemon as any).pid = 99999;
  mockDaemon.kill = (_signal?: any): boolean => true;

  const daemonState: DaemonProcessState = { child: mockDaemon, exited: false };
  const isShuttingDownFlag = { value: false };

  const res = await executeShutdownSequence({
    daemonState,
    httpServer: null,
    activeSockets: new Set(),
    isShuttingDownFlag,
    termTimeoutMs: 100,
    killTimeoutMs: 100,
    exitProcess: false
  });

  assert.equal(res.daemonExitedCleanly, false, 'daemonExitedCleanly must be false when daemon refuses to exit');
  assert.equal(res.exitCode, 1, 'exitCode must be 1 (FAILURE) when daemon refuses to exit after SIGKILL');
});

test('12. [Lifecycle Guard] Duplicate startDaemonProcess call does not spawn a second child', async () => {
  const firstChild = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)']);
  try {
    const activeState: DaemonProcessState = { child: firstChild, exited: false };
    const returnedState = startDaemonProcess(activeState, {
      pythonCmd: process.execPath,
      args: ['-e', 'process.exit(0)']
    });
    assert.strictEqual(returnedState, activeState, 'Duplicate startDaemonProcess must return existing active state');
    assert.strictEqual(returnedState.child, firstChild, 'Original daemon child reference must be preserved');
  } finally {
    await waitForChildExit(firstChild, 500, 500);
  }
});

