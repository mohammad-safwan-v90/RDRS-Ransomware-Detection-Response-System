import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  ALLOWED_ACTIONS,
  DEFAULT_MAX_STDERR_BYTES,
  DEFAULT_MAX_STDOUT_BYTES,
  callPythonBridge,
  getDefaultPythonCmd
} from '../src/python_bridge';

function createTempScript(filename: string, code: string): { dir: string; scriptPath: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rdrs_bridge_test_'));
  const scriptPath = path.join(dir, filename);
  fs.writeFileSync(scriptPath, code, 'utf-8');
  return { dir, scriptPath };
}

test('Python Bridge - Default Executable Selection & Default Limits', () => {
  const originalEnv = process.env.PYTHON_PATH;
  try {
    delete process.env.PYTHON_PATH;
    const expectedDefault = process.platform === 'win32' ? 'python' : 'python3';
    assert.equal(getDefaultPythonCmd(), expectedDefault);

    process.env.PYTHON_PATH = '/custom/bin/python3.11';
    assert.equal(getDefaultPythonCmd(), '/custom/bin/python3.11');
    assert.equal(DEFAULT_MAX_STDOUT_BYTES, 1024 * 1024);
    assert.equal(DEFAULT_MAX_STDERR_BYTES, 256 * 1024);
  } finally {
    if (originalEnv === undefined) {
      delete process.env.PYTHON_PATH;
    } else {
      process.env.PYTHON_PATH = originalEnv;
    }
  }
});

test('Python Bridge - Reject Invalid Limits (0, -1, 0.5, 1.5, NaN, Infinity) and Accept Positive Integers', async () => {
  assert.ok(ALLOWED_ACTIONS.includes('health'));
  const disallowed = await callPythonBridge('reboot_system', []);
  assert.equal(disallowed.error, 'Action not allowed');

  const invalidValues = [0, -1, 0.5, 1.5, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY];
  for (const invalid of invalidValues) {
    const badStdout = await callPythonBridge('status', [], { maxStdoutBytes: invalid });
    assert.equal(badStdout.error, 'Invalid bridge configuration', `maxStdoutBytes=${invalid} should be rejected`);

    const badStderr = await callPythonBridge('status', [], { maxStderrBytes: invalid });
    assert.equal(badStderr.error, 'Invalid bridge configuration', `maxStderrBytes=${invalid} should be rejected`);

    const badTimeout = await callPythonBridge('status', [], { timeoutMs: invalid });
    assert.equal(badTimeout.error, 'Invalid bridge configuration', `timeoutMs=${invalid} should be rejected`);
  }

  // Valid positive integer values should be accepted cleanly
  const { dir, scriptPath } = createTempScript(
    'valid_int.py',
    'import sys, json\nsys.stdout.write(json.dumps({"ok": True}) + "\\n")\nsys.stdout.flush()\n'
  );
  try {
    const validRes = await callPythonBridge('status', [], {
      scriptPath,
      cwd: dir,
      maxStdoutBytes: 1024,
      maxStderrBytes: 512,
      timeoutMs: 5000
    });
    assert.equal(validRes.error, undefined);
    assert.equal(validRes.ok, true);

    const minIntRes = await callPythonBridge('status', [], {
      scriptPath,
      cwd: dir,
      maxStdoutBytes: 1,
      maxStderrBytes: 1,
      timeoutMs: 1000
    });
    // maxStdoutBytes=1 is valid config (triggers Output limit exceeded on chunk, NOT Invalid bridge configuration)
    assert.equal(minIntRes.error, 'Output limit exceeded');
  } finally {
    await fs.promises.rm(dir, {
      recursive: true,
      force: true,
      maxRetries: 10,
      retryDelay: 100
    });
  }
});

test('Python Bridge - Real CLI Argument Separation (No Shell Injection)', async () => {
  const payload = '; echo INJECTED_SHELL && uname -a';
  const res = await callPythonBridge('entropy', [payload], { cwd: process.cwd() });
  assert.equal(res.error, undefined);
  assert.equal(typeof res.entropy, 'number');
  assert.equal(res.length, Buffer.byteLength(payload, 'utf-8'));
});

test('Python Bridge - Real CLI Read Endpoints Normal Responses', async () => {
  const actions = ['health', 'status', 'history', 'alerts', 'events', 'incidents'] as const;
  for (const action of actions) {
    const res = await callPythonBridge(action, [], { cwd: process.cwd() });
    assert.equal(res.error, undefined, `Expected no error for ${action}, got: ${JSON.stringify(res)}`);
  }
});

test('Python Bridge - Spawn Failure on Non-Existent Executable', async () => {
  const res = await callPythonBridge('status', [], {
    pythonCmd: 'nonexistent_python_binary_xyz_999'
  });
  assert.equal(res.error, 'Spawn failed');
  assert.ok(res.details);
});

test('Python Bridge - Non-Zero Exit Code & stderr Capture', async () => {
  const { dir, scriptPath } = createTempScript(
    'fail_cli.py',
    'import sys\nsys.stderr.write("fatal_cli_failure")\nsys.exit(2)\n'
  );
  try {
    const res = await callPythonBridge('status', [], { scriptPath, cwd: dir });
    assert.equal(res.error, 'Python execution failed');
    assert.equal(res.code, 2);
    assert.match(res.details, /fatal_cli_failure/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Python Bridge - Noisy Stdout JSON Extraction & Unparseable Output Failure', async () => {
  const { dir: noisyDir, scriptPath: noisyScript } = createTempScript(
    'noisy_cli.py',
    'import json\nprint("WARNING: informational banner")\nprint(json.dumps({"status": "ok", "count": 3}))\nprint("trailing debug line")\n'
  );
  const { dir: badDir, scriptPath: badScript } = createTempScript(
    'bad_cli.py',
    'print("definitely not json at all")\n'
  );
  try {
    const noisyRes = await callPythonBridge('status', [], { scriptPath: noisyScript, cwd: noisyDir });
    assert.equal(noisyRes.status, 'ok');
    assert.equal(noisyRes.count, 3);

    const badRes = await callPythonBridge('status', [], { scriptPath: badScript, cwd: badDir });
    assert.equal(badRes.error, 'JSON parse failed');
  } finally {
    fs.rmSync(noisyDir, { recursive: true, force: true });
    fs.rmSync(badDir, { recursive: true, force: true });
  }
});

test('Python Bridge - Output Just Below Limit Succeeds and 1 Byte Over Fails', async () => {
  const payload = JSON.stringify({ status: 'ok', data: 'a'.repeat(500) }) + '\n';
  const exactBytes = Buffer.byteLength(payload, 'utf8');
  const { dir, scriptPath } = createTempScript(
    'boundary_ok.py',
    'import sys, json\nsys.stdout.write(json.dumps({"status": "ok", "data": "a" * 500}, separators=(",", ":")) + "\\n")\nsys.stdout.flush()\n'
  );
  try {
    const belowLimitRes = await callPythonBridge('status', [], {
      scriptPath,
      cwd: dir,
      maxStdoutBytes: exactBytes + 1
    });
    assert.equal(belowLimitRes.error, undefined);
    assert.equal(belowLimitRes.status, 'ok');
    assert.equal(belowLimitRes.data.length, 500);

    const overLimitRes = await callPythonBridge('status', [], {
      scriptPath,
      cwd: dir,
      maxStdoutBytes: exactBytes - 1
    });
    assert.equal(overLimitRes.error, 'Output limit exceeded');
    assert.equal(overLimitRes.stream, 'stdout');
  } finally {
    await fs.promises.rm(dir, {
      recursive: true,
      force: true,
      maxRetries: 10,
      retryDelay: 100
    });
  }
});

test('Python Bridge - Streaming Stdout Exceeding Limit Terminates Child Safely', async () => {
  const pidMarkerDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rdrs_pid_out_'));
  const pidFile = path.join(pidMarkerDir, 'child.pid');
  const { dir, scriptPath } = createTempScript(
    'flood_stdout.py',
    `import os, sys, time
with open(${JSON.stringify(pidFile)}, "w") as f:
    f.write(str(os.getpid()))
chunk = "X" * 1024
while True:
    sys.stdout.write(chunk)
    sys.stdout.flush()
    time.sleep(0.01)
`
  );
  try {
    const startedAt = Date.now();
    const res = await callPythonBridge('status', [], {
      scriptPath,
      cwd: dir,
      maxStdoutBytes: 2048,
      timeoutMs: 8000
    });
    const elapsed = Date.now() - startedAt;

    assert.equal(res.error, 'Output limit exceeded');
    assert.equal(res.stream, 'stdout');
    assert.equal(res.maxBytes, 2048);
    assert.ok(elapsed < 4000, `Expected immediate termination on stdout overflow, took ${elapsed}ms`);

    // Give OS brief window to reap terminated child process and confirm it is gone
    await new Promise((r) => setTimeout(r, 150));
    if (fs.existsSync(pidFile)) {
      const pid = Number(fs.readFileSync(pidFile, 'utf8').trim());
      assert.throws(() => process.kill(pid, 0), 'Child process should be terminated after stdout overflow');
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(pidMarkerDir, { recursive: true, force: true });
  }
});

test('Python Bridge - Streaming Stderr Exceeding Limit Terminates Child Safely', async () => {
  const pidMarkerDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rdrs_pid_err_'));
  const pidFile = path.join(pidMarkerDir, 'child.pid');
  const { dir, scriptPath } = createTempScript(
    'flood_stderr.py',
    `import os, sys, time
with open(${JSON.stringify(pidFile)}, "w") as f:
    f.write(str(os.getpid()))
chunk = "E" * 512
while True:
    sys.stderr.write(chunk)
    sys.stderr.flush()
    time.sleep(0.01)
`
  );
  try {
    const startedAt = Date.now();
    const res = await callPythonBridge('status', [], {
      scriptPath,
      cwd: dir,
      maxStderrBytes: 1024,
      timeoutMs: 8000
    });
    const elapsed = Date.now() - startedAt;

    assert.equal(res.error, 'Stderr limit exceeded');
    assert.equal(res.stream, 'stderr');
    assert.equal(res.maxBytes, 1024);
    assert.ok(elapsed < 4000, `Expected immediate termination on stderr overflow, took ${elapsed}ms`);

    await new Promise((r) => setTimeout(r, 150));
    if (fs.existsSync(pidFile)) {
      const pid = Number(fs.readFileSync(pidFile, 'utf8').trim());
      assert.throws(() => process.kill(pid, 0), 'Child process should be terminated after stderr overflow');
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(pidMarkerDir, { recursive: true, force: true });
  }
});

test('Python Bridge - Large 100KB Output Under Default 1MiB Limit', async () => {
  const { dir, scriptPath } = createTempScript(
    'large_cli.py',
    'import json\nprint(json.dumps({"data": "x" * 100000}))\n'
  );
  try {
    const res = await callPythonBridge('status', [], { scriptPath, cwd: dir });
    assert.equal(res.error, undefined);
    assert.equal(res.data.length, 100000);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Python Bridge - Timeout Kills Hanging Process & Resolves Once', async () => {
  const { dir, scriptPath } = createTempScript(
    'hang_cli.py',
    'import signal, time\nsignal.signal(signal.SIGTERM, lambda s, f: None)\ntime.sleep(5)\n'
  );
  try {
    const res = await callPythonBridge('status', [], { scriptPath, cwd: dir, timeoutMs: 250 });
    assert.equal(res.error, 'Python execution timed out');
    await new Promise((r) => setTimeout(r, 350));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Python Bridge - Repeated Concurrent Calls & Nullish Arg Coercion', async () => {
  const results = await Promise.all([
    callPythonBridge('status', [], { cwd: process.cwd() }),
    callPythonBridge('health', [], { cwd: process.cwd() }),
    callPythonBridge('status', [], { cwd: process.cwd() }),
    callPythonBridge('entropy', [undefined as unknown as string], { cwd: process.cwd() })
  ]);
  for (const res of results.slice(0, 3)) {
    assert.equal(res.error, undefined, `Expected clean repeated response, got: ${JSON.stringify(res)}`);
  }
  assert.equal(results[3].error, undefined);
  assert.equal(results[3].entropy, 0);
});

