import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import {
  startDaemonProcess as startDaemonProcessHelper,
  executeShutdownSequence,
  DaemonProcessState
} from './src/server_lifecycle';
import { callPythonBridge as runPythonBridge, getDefaultPythonCmd } from './src/python_bridge';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PYTHON_CMD = getDefaultPythonCmd();

let daemonState: DaemonProcessState = {
  child: null,
  exited: true
};
let httpServerInstance: any = null;
const shuttingDownFlag = { value: false };
const activeSockets = new Set<any>();

function startDaemonProcess() {
  daemonState = startDaemonProcessHelper(daemonState, {
    pythonCmd: PYTHON_CMD,
    daemonScript: 'rdrs_daemon.py',
    cwd: process.cwd(),
    isShuttingDown: () => shuttingDownFlag.value
  });
}

const gracefulShutdown = async (signalName: string) => {
  console.log(`[Express Server] Received signal ${signalName}. Initiating shutdown...`);
  await executeShutdownSequence({
    daemonState,
    httpServer: httpServerInstance,
    activeSockets,
    isShuttingDownFlag: shuttingDownFlag,
    termTimeoutMs: 4000,
    killTimeoutMs: 2000,
    httpTimeoutMs: 3000,
    exitProcess: true
  });
};

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

async function callPythonBridge(
  action: string,
  args: string[] = [],
  options: { timeoutMs?: number } = {}
): Promise<any> {
  return runPythonBridge(action, args, {
    pythonCmd: PYTHON_CMD,
    cwd: process.cwd(),
    ...options
  });
}

function sendBridgeResponse(res: express.Response, data: any) {
  if (data && data.error) {
    const explicitStatus =
      typeof data.status_code === 'number' && data.status_code >= 400 && data.status_code < 600
        ? data.status_code
        : null;
    const status =
      explicitStatus ??
      (data.error === 'Action not allowed' || data.error === 'Invalid bridge configuration'
        ? 400
        : data.error === 'Python execution timed out' || data.error === 'Spawn failed'
        ? 503
        : 500);
    res.status(status).json(data);
    return;
  }
  res.json(data);
}

const asyncHandler =
  (fn: (req: express.Request, res: express.Response, next: express.NextFunction) => Promise<any>) =>
  (req: express.Request, res: express.Response, next: express.NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };

async function startServer() {
  startDaemonProcess();
  const app = express();

  app.use(express.json());

  // API Endpoints
  app.get('/api/health', asyncHandler(async (_req, res) => {
    const data = await callPythonBridge('health');
    if (data?.error) {
      res.status(503).json({
        status: 'degraded',
        service: 'RDRS Python Detection Core',
        daemon_monitoring: false,
        database_accessible: false,
        error: data.error,
        details: data.details,
        timestamp: new Date().toISOString()
      });
      return;
    }
    const httpStatus = data?.status === 'healthy' ? 200 : 503;
    res.status(httpStatus).json(data);
  }));

  app.get('/api/status', asyncHandler(async (_req, res) => {
    const data = await callPythonBridge('status');
    sendBridgeResponse(res, data);
  }));

  app.get('/api/alerts', asyncHandler(async (req, res) => {
    const severity = typeof req.query.severity === 'string' ? req.query.severity : '';
    const data = await callPythonBridge('alerts', [severity]);
    sendBridgeResponse(res, data);
  }));

  app.post('/api/alerts/update', asyncHandler(async (req, res) => {
    const { alertId, status } = req.body || {};
    if (alertId === undefined || alertId === null || alertId === '' || typeof status !== 'string' || !status.trim()) {
      res.status(400).json({ error: 'Missing or invalid alertId or status' });
      return;
    }
    const data = await callPythonBridge('update_alert', [String(alertId), status.trim()]);
    sendBridgeResponse(res, data);
  }));

  app.get('/api/events', asyncHandler(async (req, res) => {
    const type = typeof req.query.type === 'string' ? req.query.type : '';
    const search = typeof req.query.search === 'string' ? req.query.search : '';
    const data = await callPythonBridge('events', [type, search]);
    sendBridgeResponse(res, data);
  }));

  app.get('/api/incidents', asyncHandler(async (_req, res) => {
    const data = await callPythonBridge('incidents');
    sendBridgeResponse(res, data);
  }));

  app.get('/api/history', asyncHandler(async (_req, res) => {
    const data = await callPythonBridge('history');
    sendBridgeResponse(res, data);
  }));

  app.post('/api/incidents/update', asyncHandler(async (req, res) => {
    const { incidentId, status } = req.body || {};
    if (typeof incidentId !== 'string' || !incidentId.trim() || typeof status !== 'string' || !status.trim()) {
      res.status(400).json({ error: 'Missing or invalid incidentId or status' });
      return;
    }
    const data = await callPythonBridge('update_incident', [incidentId.trim(), status.trim()]);
    sendBridgeResponse(res, data);
  }));

  app.post('/api/entropy/calculate', asyncHandler(async (req, res) => {
    const text = typeof req.body?.text === 'string' ? req.body.text : '';
    const data = await callPythonBridge('entropy', [text]);
    sendBridgeResponse(res, data);
  }));

  app.post('/api/simulator/run', asyncHandler(async (req, res) => {
    const attackType =
      typeof req.body?.attackType === 'string' && req.body.attackType.trim()
        ? req.body.attackType.trim()
        : 'entropy_spike';
    const data = await callPythonBridge('simulator', [attackType], { timeoutMs: 60000 });
    sendBridgeResponse(res, data);
  }));

  app.get('/api/tests/run', asyncHandler(async (_req, res) => {
    const data = await callPythonBridge('run_tests', [], { timeoutMs: 60000 });
    sendBridgeResponse(res, data);
  }));

  // Server-Sent Events (SSE) Stream for real-time zero-reload dashboard updates
  app.get('/api/stream', async (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    let clientClosed = false;
    let updateInProgress = false;

    const sendUpdate = async () => {
      if (clientClosed || shuttingDownFlag.value || res.writableEnded || res.destroyed) {
        return;
      }
            if (updateInProgress) {
        return;
      }
      updateInProgress = true;
      try {
        const dashboard = await callPythonBridge('dashboard');
        const status = dashboard?.status;
        const alerts = { alerts: dashboard?.alerts ?? [] };
        const events = { events: dashboard?.events ?? [] };
        const incident = { incident: dashboard?.incident ?? null };
        const history = { history: dashboard?.history ?? [] };

        if (clientClosed || shuttingDownFlag.value || res.writableEnded || res.destroyed) {
          return;
        }
        const payload = JSON.stringify({
          status,
          alerts: Array.isArray(alerts?.alerts) ? alerts.alerts : [],
          events: Array.isArray(events?.events) ? events.events : [],
          incident: incident?.incident || null,
          history: Array.isArray(history?.history) ? history.history : []
        });
        res.write(`data: ${payload}\n\n`);
      } catch (err) {
        console.error(`[${new Date().toISOString()}] SSE Stream error:`, err);
      }
      finally {
        updateInProgress = false;
      }
    };

    const interval = setInterval(sendUpdate, 10000);

    req.on('close', () => {
      clientClosed = true;
      clearInterval(interval);
    });

    // Send initial frame
    await sendUpdate();
  });

  app.use('/api', (err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error(`[${new Date().toISOString()}] Express API Error:`, err);
    if (err instanceof SyntaxError && 'body' in err) {
      res.status(400).json({ error: 'Invalid JSON request body', details: err.message });
      return;
    }
    res.status(500).json({ error: 'Internal server error', details: err?.message || 'Unexpected failure' });
  });

  const isProduction = process.env.NODE_ENV === 'production' || (fs.existsSync(path.resolve(__dirname, 'index.html')) && fs.existsSync(path.resolve(__dirname, 'assets')));

  if (isProduction) {
    app.use(express.static(__dirname));
    app.get('*', (req, res) => {
      res.sendFile(path.resolve(__dirname, 'index.html'));
    });
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'custom',
    });
    app.use(vite.middlewares);

    app.use('*', async (req, res, next) => {
      const url = req.originalUrl;
      try {
        let template = fs.readFileSync(path.resolve(__dirname, 'index.html'), 'utf-8');
        template = await vite.transformIndexHtml(url, template);
        res.status(200).set({ 'Content-Type': 'text/html' }).end(template);
      } catch (e: any) {
        vite.ssrFixStacktrace(e);
        next(e);
      }
    });
  }

  const numericPort = Number(process.env.PORT) || 3000;
  httpServerInstance = app.listen(numericPort, '0.0.0.0', () => {
    console.log(`RDRS Python-Backed SSE Server running on http://0.0.0.0:${numericPort}`);
  });

  httpServerInstance.on('connection', (socket: any) => {
    activeSockets.add(socket);
    socket.on('close', () => activeSockets.delete(socket));
  });
}

startServer();
