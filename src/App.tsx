import React, { useState, useEffect } from 'react';
import {
  Shield,
  AlertTriangle,
  Activity,
  FileText,
  Terminal,
  Download,
  CheckCircle2,
  Server,
  Zap,
  Play,
  RefreshCw,
  Lock,
  BookOpen,
  Code,
  ChevronRight,
  FileCheck,
  AlertCircle,
  X,
  Search,
  Filter,
  Check,
  Info,
  Clock,
  Eye,
  FileCode,
  CheckSquare
} from 'lucide-react';
import {
  AreaChart,
  Area,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer
} from 'recharts';

export default function App() {
  const [activeTab, setActiveTab] = useState<
    'dashboard' | 'alerts' | 'events' | 'incidents' | 'reports' | 'api' | 'simulator' | 'tests' | 'docker' | 'mentor'
  >('dashboard');

  const [systemState, setSystemState] = useState({
    threat_level: 'Connecting...',
    threat_score: 0,
    active_alerts_count: 0,
    total_events_count: 0,
    is_monitoring: false,
    daemon_pid: null as number | null,
    daemon_reason: 'Checking daemon...',
    simulation_mode: true,
    cpu_usage: 0,
    avg_entropy: 0,
    last_updated: ''
  });

  const [alertsList, setAlertsList] = useState<any[]>([]);
  const [eventsList, setEventsList] = useState<any[]>([]);
  const [incidentData, setIncidentData] = useState<any>(null);
  const [threatHistory, setThreatHistory] = useState<any[]>([]);
  const [isSseConnected, setIsSseConnected] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [backendError, setBackendError] = useState<string | null>(null);
  const [isRunningTests, setIsRunningTests] = useState<boolean>(false);

  // Filters & Selected Modals
  const [alertSeverityFilter, setAlertSeverityFilter] = useState<string>('All');
  const [eventSearch, setEventSearch] = useState<string>('');
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('All');

  const [selectedAlert, setSelectedAlert] = useState<any | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<any | null>(null);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [confirmDialog, setConfirmDialog] = useState<{ title: string; action: () => void } | null>(null);

  // Calculator & Test state
  const [calcInput, setCalcInput] = useState<string>('Sample plain text line for Shannon entropy testing.');
  const [calcResult, setCalcResult] = useState<any>(null);
  const [simStatus, setSimStatus] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<any>(null);
  const [apiConsoleOutput, setApiConsoleOutput] = useState<any>(null);

  useEffect(() => {

    

    // Connect Server-Sent Events (SSE) for zero-reload real-time dashboard pushes
    const es = new EventSource('/api/stream');
    es.onopen = () => {
      setIsSseConnected(true);
      setBackendError(null);
    };
    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        if (data.status && !data.status.error) setSystemState(data.status);
        if (data.alerts) setAlertsList(data.alerts);
        if (data.events) setEventsList(data.events);
        if (data.incident) setIncidentData(data.incident);
        if (data.history) setThreatHistory(data.history);
        setIsLoading(false);
      } catch (err) {
        console.error('SSE JSON error:', err);
      }
    };
    es.onerror = () => setIsSseConnected(false);

    return () => es.close();
  }, []);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 4000);
  };

  const entropyRequestId = React.useRef(0);


  const fetchBackendData = async () => {
    try {
      const params = new URLSearchParams({
        severity: alertSeverityFilter,
        type: eventTypeFilter,
        search: eventSearch
      });

      const res = await fetch(`/api/dashboard?${params.toString()}`);
      const data = await res.json().catch(() => null);

      if (!res.ok || data?.error) {
        throw new Error(data?.error || `Dashboard endpoint returned HTTP ${res.status}`);
      }

      setSystemState(data.status);
      setAlertsList(data.alerts || []);
      setEventsList(data.events || []);
      setIncidentData(data.incident);
      setThreatHistory(data.history || []);
      setBackendError(null);

    } catch (e: any) {
      console.error(e);
      setBackendError(e?.message || 'Unable to synchronize with RDRS backend');
    } finally {
      setIsLoading(false);
    }
  };

  const calculateEntropy = async (text: string) => {
    const reqId = ++entropyRequestId.current;
    try {
      const res = await fetch('/api/entropy/calculate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text })
      });
      const data = await res.json().catch(() => null);
      if (reqId !== entropyRequestId.current) return;
      if (res.ok && data && !data.error) {
        setCalcResult(data);
      } else {
        setCalcResult({ error: data?.error || `Entropy check failed (HTTP ${res.status})` });
      }
    } catch (e: any) {
      console.error(e);
      if (reqId === entropyRequestId.current) {
        setCalcResult({ error: e?.message || 'Network error calculating entropy' });
      }
    }
  };

  const updateAlertStatus = async (alertId: number, status: 'Acknowledged' | 'Resolved') => {
    try {
      const res = await fetch('/api/alerts/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alertId, status })
      });
      const data = await res.json();
      if (res.ok && !data?.error) {
        showToast(`Alert #${alertId} marked as ${status}`);
        fetchBackendData();
        setSelectedAlert(null);
      } else {
        showToast(`Failed to update alert: ${data?.error || res.statusText}`);
      }
    } catch (e: any) {
      console.error(e);
      showToast(`Error updating alert: ${e?.message || 'Network error'}`);
    }
  };

  const updateIncidentStatus = async (status: string) => {
    if (!incidentData?.incident_id) return;
    try {
      const res = await fetch('/api/incidents/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ incidentId: incidentData.incident_id, status })
      });
      const data = await res.json();
      if (res.ok && !data?.error) {
        showToast(`Incident status updated to '${status}'`);
        fetchBackendData();
      } else {
        showToast(`Failed to update incident: ${data?.error || res.statusText}`);
      }
    } catch (e: any) {
      console.error(e);
      showToast(`Error updating incident: ${e?.message || 'Network error'}`);
    }
  };

  const runSimulation = async (attackType: string) => {
    setSimStatus('Executing Python detection engine in safe sandbox...');
    try {
      const res = await fetch('/api/simulator/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attackType })
      });
      const data = await res.json();
      if (res.ok && !data?.error) {
        setSimStatus(data.message);
        showToast(data.message);
        fetchBackendData();
      } else {
        const errMsg = data?.error || `HTTP ${res.status}`;
        setSimStatus(`Simulation failed: ${errMsg}`);
        showToast(`Simulation failed: ${errMsg}`);
      }
    } catch (e: any) {
      setSimStatus(`Simulation execution error: ${e?.message || 'Network error'}`);
    }
  };

  const testApiEndpoint = async (endpoint: string, method: string = 'GET', body?: any) => {
    try {
      const options: RequestInit = { method, headers: { 'Content-Type': 'application/json' } };
      if (body) options.body = JSON.stringify(body);
      const res = await fetch(endpoint, options);
      const data = await res.json();
      setApiConsoleOutput({ endpoint, method, status: res.status, response: data });
    } catch (e: any) {
      setApiConsoleOutput({ endpoint, method, status: 500, response: { error: e.message } });
    }
  };

  const runTests = async () => {
    setIsRunningTests(true);
    try {
      const res = await fetch('/api/tests/run');
      const data = await res.json().catch(() => null);
      if (res.ok && data && !data.error) {
        setTestResult(data);
      } else {
        setTestResult({
          error: data?.error || `Test runner returned HTTP ${res.status}`,
          details: data?.details || null,
          success: false
        });
      }
    } catch (e: any) {
      console.error(e);
      setTestResult({
        error: e?.message || 'Failed to execute Python test suite',
        success: false
      });
    } finally {
      setIsRunningTests(false);
    }
  };

  const escapeHtml = (value: unknown): string =>
    String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');

  const csvCell = (value: unknown): string => `"${String(value ?? '').replace(/"/g, '""')}"`;

  const downloadReport = (format: 'json' | 'csv' | 'html') => {
    let content = '';
    const safeId = String(incidentData?.incident_id || 'INC-001').replace(/[^a-zA-Z0-9_-]/g, '_');
    const filename = `incident_${safeId}.${format}`;
    let mimeType = 'application/json';

    if (format === 'json') {
      content = JSON.stringify(incidentData || {}, null, 2);
    } else if (format === 'csv') {
      mimeType = 'text/csv';
      content = [
        'incident_id,timestamp,threat_score,severity,affected_files',
        [
          csvCell(incidentData?.incident_id || 'INC-001'),
          csvCell(incidentData?.timestamp || ''),
          csvCell(incidentData?.threat_score || 0),
          csvCell(incidentData?.severity || 'Normal'),
          csvCell(incidentData?.affected_files_count || 0)
        ].join(',')
      ].join('\n');
    } else if (format === 'html') {
      mimeType = 'text/html';
      const escId = escapeHtml(incidentData?.incident_id || 'INC-001');
      const escScore = escapeHtml(incidentData?.threat_score ?? 0);
      const escSeverity = escapeHtml(incidentData?.severity || 'Normal');
      const escTs = escapeHtml(incidentData?.timestamp || '');
      const signalsHtml = (incidentData?.detection_signals || [])
        .map((s: string) => `<li>${escapeHtml(s)}</li>`)
        .join('');
      const filesHtml = (incidentData?.affected_files || [])
        .map((f: string) => `<li><code>${escapeHtml(f)}</code></li>`)
        .join('');
      content = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>RDRS Incident Report - ${escId}</title></head><body style="font-family:sans-serif;background:#0f172a;color:#fff;padding:2rem;"><h1>RDRS Incident Report ${escId}</h1><p>Timestamp: ${escTs}</p><p>Threat Score: ${escScore}/100 (${escSeverity})</p><h3>Detection Signals</h3><ul>${signalsHtml}</ul><h3>Affected Files</h3><ul>${filesHtml}</ul></body></html>`;
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
    showToast(`Downloaded ${format.toUpperCase()} incident report`);
  };

  // Real threat history from backend
  const chartData = threatHistory;

  const filteredAlerts = alertsList.filter((a) => {
    if (alertSeverityFilter === 'All') return true;
    return a.severity === alertSeverityFilter;
  });

  const filteredEvents = eventsList.filter((e) => {
    const matchesSearch = !eventSearch || e.file_path.toLowerCase().includes(eventSearch.toLowerCase());
    const matchesType = eventTypeFilter === 'All' || e.event_type.toLowerCase() === eventTypeFilter.toLowerCase();
    return matchesSearch && matchesType;
  });

  return (
    <div className="flex h-screen bg-[#090d16] text-slate-100 font-sans overflow-hidden">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 p-4 rounded-xl bg-slate-800 border border-cyan-500/50 text-xs text-cyan-300 shadow-2xl flex items-center gap-3 animate-bounce">
          <CheckCircle2 className="w-5 h-5 text-cyan-400 shrink-0" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Confirmation Modal */}
      {confirmDialog && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="p-6 rounded-xl bg-slate-900 border border-slate-700 max-w-md w-full space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-amber-500" />
              Confirm Action
            </h3>
            <p className="text-xs text-slate-300">{confirmDialog.title}</p>
            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setConfirmDialog(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-semibold"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  confirmDialog.action();
                  setConfirmDialog(null);
                }}
                className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg text-xs font-semibold shadow"
              >
                Confirm
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Alert Details Modal */}
      {selectedAlert && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="p-6 rounded-xl bg-slate-900 border border-slate-700 max-w-lg w-full space-y-4 shadow-2xl relative">
            <button
              onClick={() => setSelectedAlert(null)}
              className="absolute top-4 right-4 text-slate-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-3">
              <span className={`px-2.5 py-1 rounded text-xs font-bold ${selectedAlert.severity === 'Critical' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'}`}>
                {selectedAlert.severity}
              </span>
              <h3 className="text-base font-bold text-white">Alert #{selectedAlert.id} Details</h3>
            </div>
            <p className="text-xs text-slate-300">{selectedAlert.message}</p>
            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs space-y-1">
              <div className="flex justify-between"><span className="text-slate-400">Timestamp:</span><span className="font-mono text-slate-200">{selectedAlert.timestamp}</span></div>
              <div className="flex justify-between"><span className="text-slate-400">Threat Score:</span><span className="font-bold text-red-400 font-mono">{selectedAlert.threat_score}/100</span></div>
              <div className="flex justify-between"><span className="text-slate-400">Status:</span><span className="font-bold text-cyan-400">{selectedAlert.status}</span></div>
            </div>
            <div>
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">Detection Signals</h4>
              <ul className="space-y-1 text-xs">
                {(selectedAlert.detection_signals || []).map((s: string, idx: number) => (
                  <li key={idx} className="p-2 rounded bg-slate-800 text-cyan-300 font-mono">● {s}</li>
                ))}
              </ul>
            </div>
            <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                onClick={() => updateAlertStatus(selectedAlert.id, 'Acknowledged')}
                className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg"
              >
                Acknowledge
              </button>
              <button
                onClick={() => updateAlertStatus(selectedAlert.id, 'Resolved')}
                className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold rounded-lg"
              >
                Mark Resolved
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Sidebar Navigation */}
      <aside className="w-64 bg-[#0d1424] border-r border-slate-800 flex flex-col justify-between p-4 shrink-0">
        <div>
          <div className="flex items-center gap-3 px-2 py-3 mb-6 border-b border-slate-800">
            <div className="p-2 bg-gradient-to-br from-blue-600 to-cyan-500 rounded-xl shadow-lg shadow-blue-500/20">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="font-bold text-lg leading-tight tracking-wide text-white">RDRS</h1>
              <p className="text-xs text-slate-400">Ransomware Detection</p>
            </div>
          </div>

          <nav className="space-y-1">
            {[
              { id: 'dashboard', label: 'Dashboard', icon: Activity },
              { id: 'alerts', label: 'Alerts', icon: AlertTriangle, badge: systemState.active_alerts_count ? `${systemState.active_alerts_count}` : undefined },
              { id: 'events', label: 'File Events', icon: FileText },
              { id: 'incidents', label: 'Incidents', icon: Shield },
              { id: 'reports', label: 'Reports', icon: FileCheck },
              { id: 'simulator', label: 'Sandbox Simulator', icon: Play, highlight: true },
              { id: 'api', label: 'REST API Docs', icon: Code },
              { id: 'tests', label: 'Python Unittest Suite', icon: Terminal, badge: testResult ? `${testResult.passed}/${testResult.tests_run}` : undefined },
              { id: 'docker', label: 'Docker & Config', icon: Server },
              { id: 'mentor', label: 'Project Architecture Guide', icon: BookOpen }
            ].map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id as any)}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                    isActive
                      ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30 font-semibold'
                      : item.highlight
                      ? 'text-cyan-400 hover:bg-slate-800/80 hover:text-cyan-300'
                      : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <Icon className={`w-4 h-4 ${isActive ? 'text-white' : item.highlight ? 'text-cyan-400' : 'text-slate-400'}`} />
                    <span>{item.label}</span>
                  </div>
                  {item.badge && (
                    <span
                      className={`text-xs px-2 py-0.5 rounded-full font-bold ${
                        isActive ? 'bg-white text-blue-600' : 'bg-red-500/20 text-red-400 border border-red-500/30'
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Real-Time Daemon & SSE Stream Status */}
        <div className="p-3 bg-slate-900/80 rounded-xl border border-slate-800/80 space-y-1.5">
          <div className="flex items-center justify-between text-xs">
            <span className={`flex items-center gap-1.5 font-medium ${isSseConnected ? 'text-emerald-400' : 'text-amber-400'}`}>
              <span className={`w-2 h-2 rounded-full ${isSseConnected ? 'bg-emerald-500 animate-pulse' : 'bg-amber-500'}`}></span>
              {isSseConnected ? 'SSE Live Stream: Active' : 'Polling Sync'}
            </span>
          </div>
          <div className="flex items-center justify-between text-[11px]">
            <span className={`flex items-center gap-1.5 font-medium ${systemState.is_monitoring ? 'text-emerald-400' : 'text-red-400'}`}>
              <span className={`w-2 h-2 rounded-full ${systemState.is_monitoring ? 'bg-emerald-500' : 'bg-red-500'}`}></span>
              {systemState.is_monitoring
                ? `Daemon Active${systemState.daemon_pid ? ` (PID ${systemState.daemon_pid})` : ''}`
                : `Daemon Offline (${systemState.daemon_reason || 'Checking'})`}
            </span>
          </div>
          <div className="flex items-center justify-between text-[11px] text-slate-400">
            <span>Simulation: {systemState.simulation_mode ? 'ON (Safe)' : 'OFF'}</span>
            <span>CPU: {systemState.cpu_usage}%</span>
          </div>
          <p className="text-[11px] text-slate-400">Target Path: ./data/sandbox</p>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col overflow-hidden bg-[#0a0f1d]">
        <header className="h-16 border-b border-slate-800 bg-[#0d1424]/60 px-6 flex items-center justify-between shrink-0">
          <div>
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              Ransomware Detection & Response System
              <span className="text-xs font-normal text-slate-400 px-2 py-0.5 rounded bg-slate-800 border border-slate-700">
                Python SOC Engine
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              Real-time Watchdog file monitoring, Shannon entropy calculations, SQLite database persistence & automated response
            </p>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right text-xs">
              <span className="text-slate-400">Last Event: </span>
              <span className="font-mono text-slate-200">{systemState.last_updated || 'Live'}</span>
            </div>
            <button
              onClick={() => {
                fetchBackendData();
                showToast('Synchronized live state from SQLite database');
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20"
            >
              <RefreshCw className="w-3 h-3" /> Sync SQLite
            </button>
          </div>
        </header>

        {/* Dynamic View Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {backendError && (
            <div className="p-3 rounded-xl bg-red-950/60 border border-red-700/60 text-xs text-red-200 flex items-center justify-between">
              <span className="flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
                Backend synchronization warning: {backendError}
              </span>
              <button
                onClick={fetchBackendData}
                className="px-2.5 py-1 rounded bg-red-800/70 hover:bg-red-700 text-white font-semibold"
              >
                Retry
              </button>
            </div>
          )}

          {isLoading && (
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-xs text-cyan-300">
              Synchronizing initial telemetry from SQLite and Python detection daemon...
            </div>
          )}

          {/* TAB 1: DASHBOARD */}
          {activeTab === 'dashboard' && (
            <>
              {/* Metric KPI Cards */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="p-4 rounded-xl bg-gradient-to-br from-red-950/40 to-slate-900 border border-red-900/40 relative overflow-hidden">
                  <div className="flex items-center justify-between text-slate-400 text-xs font-medium mb-2">
                    <span>Threat Level</span>
                    <AlertTriangle className="w-4 h-4 text-red-500" />
                  </div>
                  <div className={`text-2xl font-bold tracking-wide flex items-center gap-2 ${
                    systemState.threat_level === 'Critical'
                      ? 'text-red-400'
                      : systemState.threat_level === 'Warning'
                      ? 'text-amber-400'
                      : systemState.threat_level === 'Normal'
                      ? 'text-emerald-400'
                      : 'text-slate-300'
                  }`}>
                    <span className={`inline-block w-3 h-3 rounded-full ${
                      systemState.threat_level === 'Critical'
                        ? 'bg-red-500 animate-ping'
                        : systemState.threat_level === 'Warning'
                        ? 'bg-amber-500 animate-ping'
                        : systemState.threat_level === 'Normal'
                        ? 'bg-emerald-500'
                        : 'bg-slate-500'
                    }`}></span>
                    {systemState.threat_level}
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1">
                    {systemState.is_monitoring ? 'Daemon Monitoring Active' : `Daemon: ${systemState.daemon_reason || 'Checking'}`}
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-gradient-to-br from-red-950/30 to-slate-900 border border-red-800/30">
                  <div className="flex items-center justify-between text-slate-400 text-xs font-medium mb-2">
                    <span>Threat Score</span>
                    <Zap className="w-4 h-4 text-amber-400" />
                  </div>
                  <div className="text-2xl font-extrabold text-white flex items-baseline gap-1">
                    <span className="text-red-400 text-3xl font-black">{systemState.threat_score}</span>
                    <span className="text-slate-500 text-sm font-normal">/ 100</span>
                  </div>
                  <div className="w-full bg-slate-800 h-2 rounded-full mt-2 overflow-hidden">
                    <div
                      className="bg-gradient-to-r from-amber-500 to-red-500 h-full transition-all duration-500"
                      style={{ width: `${systemState.threat_score}%` }}
                    ></div>
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
                  <div className="flex items-center justify-between text-slate-400 text-xs font-medium mb-2">
                    <span>SQLite File Events</span>
                    <FileText className="w-4 h-4 text-blue-400" />
                  </div>
                  <div className="text-2xl font-bold text-white font-mono">
                    {systemState.total_events_count.toLocaleString()}
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1">Watchdog event persistence</p>
                </div>

                <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
                  <div className="flex items-center justify-between text-slate-400 text-xs font-medium mb-2">
                    <span>Active Alerts</span>
                    <AlertCircle className="w-4 h-4 text-amber-500" />
                  </div>
                  <div className="text-2xl font-bold text-amber-400 font-mono">
                    {systemState.active_alerts_count}
                  </div>
                  <p className="text-[11px] text-amber-400/80 mt-1">Stored in SQLite DB</p>
                </div>
              </div>

              {/* Time Series Charts Grid */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800">
                  <h3 className="text-sm font-semibold text-slate-200 mb-4 flex items-center justify-between">
                    <span>Threat Score Evolution (Python Sliding Window)</span>
                    <span className="text-xs text-red-400 font-normal">Score: {systemState.threat_score} / 100</span>
                  </h3>
                  <div className="h-56 relative">
                    {chartData.length === 0 ? (
                      <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-500 space-y-2">
                        <Activity className="w-8 h-8 opacity-20" />
                        <p className="text-xs italic">No threat activity recorded in the last 24 hours.</p>
                      </div>
                    ) : (
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={chartData}>
                          <defs>
                            <linearGradient id="scoreColor" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="#ef4444" stopOpacity={0.8} />
                              <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                            </linearGradient>
                          </defs>
                          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                          <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
                          <YAxis domain={[0, 100]} stroke="#64748b" fontSize={11} />
                          <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', color: '#fff' }} />
                          <Area type="monotone" dataKey="score" stroke="#ef4444" strokeWidth={2} fillOpacity={1} fill="url(#scoreColor)" />
                        </AreaChart>
                      </ResponsiveContainer>
                    )}
                  </div>
                </div>

                <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col justify-between">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-200 mb-2">Real Shannon Entropy Indicator</h3>
                    <p className="text-xs text-slate-400 mb-4">Average entropy calculated across files in sandbox.</p>
                    <div className="p-4 rounded-xl bg-slate-800/80 border border-slate-700 flex items-center justify-between">
                      <div>
                        <span className="text-xs text-slate-400">Calculated Mean Entropy</span>
                        <p className="text-3xl font-black text-cyan-400 font-mono mt-1">
                          {systemState.avg_entropy} <span className="text-xs font-normal text-slate-400">bits/byte</span>
                        </p>
                      </div>
                      <div className="text-right">
                        <span className="text-xs text-slate-400">Threshold</span>
                        <p className="text-sm font-bold text-red-400 mt-1">&ge; 7.20 bits/byte</p>
                      </div>
                    </div>
                  </div>
                  <div className="pt-3 border-t border-slate-800 text-xs text-slate-400">
                    Target Monitored Folder: <code className="text-cyan-400">./data/sandbox</code>
                  </div>
                </div>
              </div>

              {/* Recent Alerts & Events preview */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-sm font-semibold text-slate-200">Recent Alerts (SQLite)</h3>
                    <button onClick={() => setActiveTab('alerts')} className="text-xs text-blue-400 hover:underline">View All</button>
                  </div>
                  <div className="space-y-2">
                    {alertsList.length === 0 ? (
                      <p className="text-xs text-slate-500 italic">No alerts recorded in SQLite.</p>
                    ) : (
                      alertsList.slice(0, 3).map((alt) => (
                        <div
                          key={alt.id}
                          onClick={() => setSelectedAlert(alt)}
                          className="p-3 rounded bg-slate-800/50 hover:bg-slate-800 border border-slate-700/60 text-xs flex justify-between cursor-pointer"
                        >
                          <div>
                            <span className="font-mono text-slate-400 mr-2">{alt.time}</span>
                            <span className="font-semibold text-white">{alt.message}</span>
                          </div>
                          <span className="font-bold text-red-400 font-mono">{alt.threat_score}/100</span>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-sm font-semibold text-slate-200">Recent Watchdog File Events</h3>
                    <button onClick={() => setActiveTab('events')} className="text-xs text-blue-400 hover:underline">View All</button>
                  </div>
                  <div className="space-y-2 font-mono text-xs">
                    {eventsList.length === 0 ? (
                      <p className="text-xs text-slate-500 italic">No events recorded in SQLite.</p>
                    ) : (
                      eventsList.slice(0, 4).map((evt, i) => (
                        <div key={i} onClick={() => setSelectedEvent(evt)} className="p-2.5 rounded bg-slate-800/40 hover:bg-slate-800 flex justify-between cursor-pointer">
                          <span className="text-slate-300 truncate max-w-[240px]">{evt.file_path}</span>
                          <span className={evt.entropy >= 7.2 ? 'text-red-400 font-bold' : 'text-emerald-400'}>
                            H: {Number(evt.entropy).toFixed(2)}
                          </span>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            </>
          )}

          {/* TAB 2: ALERTS */}
          {activeTab === 'alerts' && (
            <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-3">
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-amber-500" />
                  Security Alerts Feed (SQLite Database)
                </h3>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-400">Filter Severity:</span>
                  {['All', 'Critical', 'Warning', 'Normal'].map((sev) => (
                    <button
                      key={sev}
                      onClick={() => setAlertSeverityFilter(sev)}
                      className={`px-2.5 py-1 rounded text-xs font-medium transition-all ${
                        alertSeverityFilter === sev ? 'bg-blue-600 text-white font-bold' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                      }`}
                    >
                      {sev}
                    </button>
                  ))}
                </div>
              </div>

              <div className="space-y-3">
                {filteredAlerts.length === 0 ? (
                  <div className="p-6 text-center text-slate-500 text-xs">No alerts matching filter in SQLite database.</div>
                ) : (
                  filteredAlerts.map((alt) => (
                    <div
                      key={alt.id}
                      onClick={() => setSelectedAlert(alt)}
                      className="p-4 rounded-lg bg-slate-800/50 hover:bg-slate-800 border border-slate-700 flex justify-between items-start cursor-pointer transition-all"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-3">
                          <span className={`px-2 py-0.5 rounded text-xs font-bold ${alt.severity === 'Critical' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'}`}>
                            {alt.severity}
                          </span>
                          <span className="font-mono text-xs text-slate-400">{alt.time}</span>
                          <span className="font-semibold text-white text-sm">{alt.message}</span>
                          <span className="text-[10px] px-2 py-0.5 rounded bg-slate-950 text-cyan-400 border border-slate-800">{alt.status}</span>
                        </div>
                        <div className="flex gap-2 pt-1">
                          {(alt.detection_signals || []).map((sig: string, i: number) => (
                            <span key={i} className="text-[10px] px-2 py-0.5 rounded bg-slate-700 text-cyan-300">
                              {sig}
                            </span>
                          ))}
                        </div>
                      </div>
                      <div className="text-right">
                        <span className="text-lg font-black text-red-400 font-mono">{alt.threat_score}/100</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

          {/* TAB 3: FILE EVENTS */}
          {activeTab === 'events' && (
            <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-3">
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <FileText className="w-5 h-5 text-blue-400" />
                  File Events Log (SQLite Database)
                </h3>
                <div className="flex items-center gap-3">
                  <div className="relative">
                    <Search className="w-4 h-4 text-slate-500 absolute left-2.5 top-2.5" />
                    <input
                      type="text"
                      placeholder="Search file path..."
                      value={eventSearch}
                      onChange={(e) => setEventSearch(e.target.value)}
                      className="pl-8 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  <select
                    value={eventTypeFilter}
                    onChange={(e) => setEventTypeFilter(e.target.value)}
                    className="py-1.5 px-3 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200"
                  >
                    <option value="All">All Events</option>
                    <option value="modified">Modified</option>
                    <option value="created">Created</option>
                    <option value="renamed">Renamed</option>
                    <option value="deleted">Deleted</option>
                  </select>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs text-slate-300">
                  <thead className="bg-slate-800 text-slate-400 uppercase text-[10px] tracking-wider">
                    <tr>
                      <th className="p-3">ID</th>
                      <th className="p-3">Time</th>
                      <th className="p-3">Event</th>
                      <th className="p-3">Path</th>
                      <th className="p-3">Entropy</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 font-mono">
                    {filteredEvents.map((evt) => (
                      <tr key={evt.id} onClick={() => setSelectedEvent(evt)} className="hover:bg-slate-800/40 cursor-pointer">
                        <td className="p-3 text-slate-500">{evt.id}</td>
                        <td className="p-3 text-slate-400">{evt.timestamp}</td>
                        <td className="p-3">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-500/20 text-blue-400">
                            {evt.event_type}
                          </span>
                        </td>
                        <td className="p-3 text-slate-200">{evt.file_path}</td>
                        <td className="p-3">
                          <span className={`font-bold ${evt.entropy >= 7.2 ? 'text-red-400' : 'text-emerald-400'}`}>
                            {Number(evt.entropy).toFixed(2)}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 4: INCIDENTS */}
          {activeTab === 'incidents' && (
            <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-6">
              <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                <h3 className="text-lg font-bold text-white font-mono">Incident Details & Containment Status</h3>
                <div className="flex gap-2">
                  {['Contained (Simulation)', 'Under Investigation', 'Resolved'].map((st) => (
                    <button
                      key={st}
                      onClick={() => updateIncidentStatus(st)}
                      className={`px-3 py-1 rounded text-xs font-semibold ${incidentData?.status === st ? 'bg-cyan-600 text-white' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'}`}
                    >
                      {st}
                    </button>
                  ))}
                </div>
              </div>

              {incidentData ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
                  <div className="space-y-4">
                    <div className="p-4 rounded-lg bg-slate-800/60 border border-slate-700 space-y-2">
                      <div className="flex justify-between"><span className="text-slate-400">Incident ID:</span><span className="text-cyan-400 font-bold font-mono">{incidentData.incident_id}</span></div>
                      <div className="flex justify-between"><span className="text-slate-400">Timestamp:</span><span className="text-slate-200 font-mono">{incidentData.timestamp}</span></div>
                      <div className="flex justify-between"><span className="text-slate-400">Threat Score:</span><span className="text-red-400 font-bold font-mono">{incidentData.threat_score} / 100</span></div>
                      <div className="flex justify-between"><span className="text-slate-400">Status:</span><span className="text-emerald-400 font-bold">{incidentData.status}</span></div>
                    </div>

                    <div>
                      <h4 className="font-bold text-slate-300 uppercase tracking-wider mb-2">Detection Signals Triggered</h4>
                      <div className="space-y-1">
                        {(incidentData.detection_signals || []).map((s: string, i: number) => (
                          <div key={i} className="p-2 rounded bg-red-950/30 border border-red-900/40 text-red-300">● {s}</div>
                        ))}
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="font-bold text-slate-300 uppercase tracking-wider mb-2">Affected Files ({incidentData.affected_files?.length || 0})</h4>
                    <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700 max-h-48 overflow-y-auto space-y-1 font-mono">
                      {(incidentData.affected_files || []).map((f: string, i: number) => (
                        <div key={i} className="text-slate-300 truncate">{f}</div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <p className="text-xs text-slate-500 italic">No incidents recorded in SQLite database.</p>
              )}
            </div>
          )}

          {/* TAB 5: REPORTS */}
          {activeTab === 'reports' && (
            <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-6">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <FileCheck className="w-5 h-5 text-blue-400" />
                Incident Reports Generator (SQLite Export)
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <button onClick={() => downloadReport('csv')} className="p-5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-left">
                  <h4 className="font-bold text-white">CSV Summary Report</h4>
                  <p className="text-xs text-slate-400 mt-1">Export tabular incident summary</p>
                </button>
                <button onClick={() => downloadReport('json')} className="p-5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-left">
                  <h4 className="font-bold text-white">JSON Technical Record</h4>
                  <p className="text-xs text-slate-400 mt-1">Export machine-readable JSON payload</p>
                </button>
                <button onClick={() => downloadReport('html')} className="p-5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-left">
                  <h4 className="font-bold text-white">HTML Report</h4>
                  <p className="text-xs text-slate-400 mt-1">Export human-readable HTML document</p>
                </button>
              </div>
            </div>
          )}

          {/* TAB 6: SANDBOX SIMULATOR */}
          {activeTab === 'simulator' && (
            <div className="space-y-6">
              <div className="p-6 rounded-xl bg-slate-900 border border-cyan-800/40 space-y-4">
                <h3 className="text-lg font-bold text-cyan-400 flex items-center gap-2">
                  <Play className="w-5 h-5 text-cyan-400" />
                  Python Sandbox Ransomware Simulator
                </h3>
                <p className="text-xs text-slate-400">
                  Runs safe simulations exclusively in <code className="text-cyan-300">./data/sandbox</code>. Never modifies files outside sandbox.
                </p>

                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <button
                    onClick={() => runSimulation('create_normal')}
                    className="p-4 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-left space-y-2"
                  >
                    <span className="font-bold text-white text-sm block">Create Normal Files</span>
                    <p className="text-xs text-slate-400">Plain text files (Low entropy ~3.5).</p>
                  </button>

                  <button
                    onClick={() => runSimulation('entropy_spike')}
                    className="p-4 rounded-xl bg-gradient-to-br from-red-900/40 to-slate-900 border border-red-800/50 hover:border-red-500 text-left space-y-2"
                  >
                    <span className="font-bold text-white text-sm block">Entropy Spike (.locked)</span>
                    <p className="text-xs text-slate-400">Simulates high-entropy ransomware payload (&gt;7.9).</p>
                  </button>

                  <button
                    onClick={() => runSimulation('mass_rename')}
                    className="p-4 rounded-xl bg-gradient-to-br from-amber-900/40 to-slate-900 border border-amber-800/50 hover:border-amber-500 text-left space-y-2"
                  >
                    <span className="font-bold text-white text-sm block">Mass File Renaming</span>
                    <p className="text-xs text-slate-400">Appends .locked extension to files.</p>
                  </button>

                  <button
                    onClick={() => {
                      setConfirmDialog({
                        title: 'Are you sure you want to reset all SQLite records and clear sandbox files?',
                        action: () => runSimulation('reset')
                      });
                    }}
                    className="p-4 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-left space-y-2"
                  >
                    <span className="font-bold text-slate-200 text-sm block">Reset Sandbox & DB</span>
                    <p className="text-xs text-slate-400">Clears SQLite events and resets status.</p>
                  </button>
                </div>

                {simStatus && (
                  <div className="p-3 rounded-lg bg-slate-800 border border-slate-700 text-xs text-cyan-300 font-mono">
                    ➜ {simStatus}
                  </div>
                )}
              </div>

              {/* Live Shannon Entropy Tool */}
              <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <Activity className="w-5 h-5 text-blue-400" />
                  Live Python Shannon Entropy Calculator
                </h3>
                <textarea
                  value={calcInput}
                  onChange={(e) => {
                    setCalcInput(e.target.value);
                    calculateEntropy(e.target.value);
                  }}
                  rows={3}
                  className="w-full p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 font-mono focus:outline-none focus:border-blue-500"
                  placeholder="Type sample text to compute entropy..."
                />

                {calcResult && (
                  calcResult.error ? (
                    <div className="p-3 rounded-lg bg-red-950/60 border border-red-800 text-xs text-red-300 font-mono">
                      Entropy calculation error: {calcResult.error}
                    </div>
                  ) : (
                    <div className="p-4 rounded-lg bg-slate-800/60 border border-slate-700 grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                      <div>
                        <span className="text-slate-400">Calculated Entropy:</span>
                        <p className="text-2xl font-black text-cyan-400 font-mono">{calcResult.entropy} bits/byte</p>
                      </div>
                      <div>
                        <span className="text-slate-400">Classification:</span>
                        <p className="text-sm font-bold text-white mt-1">{calcResult.classification}</p>
                      </div>
                      <div>
                        <span className="text-slate-400">Threshold (&gt;7.2):</span>
                        <p className={`text-sm font-bold mt-1 ${calcResult.isSuspicious ? 'text-red-400' : 'text-emerald-400'}`}>
                          {calcResult.isSuspicious ? '🚨 Encrypted Payload' : '✅ Normal Data'}
                        </p>
                      </div>
                    </div>
                  )
                )}
              </div>
            </div>
          )}

          {/* TAB 7: REST API INTERACTIVE TESTER */}
          {activeTab === 'api' && (
            <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-6">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Code className="w-5 h-5 text-emerald-400" />
                Express REST API Interactive Tester
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                {[
                  { name: 'GET /api/health', action: () => testApiEndpoint('/api/health') },
                  { name: 'GET /api/status', action: () => testApiEndpoint('/api/status') },
                  { name: 'GET /api/alerts', action: () => testApiEndpoint('/api/alerts') },
                  { name: 'GET /api/events', action: () => testApiEndpoint('/api/events') },
                  { name: 'GET /api/incidents', action: () => testApiEndpoint('/api/incidents') },
                  { name: 'GET /api/history', action: () => testApiEndpoint('/api/history') },
                  { name: 'POST /api/simulator/run (Entropy Spike)', action: () => testApiEndpoint('/api/simulator/run', 'POST', { attackType: 'entropy_spike' }) }
                ].map((item, i) => (
                  <button
                    key={i}
                    onClick={item.action}
                    className="p-3 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-left text-cyan-300 font-bold flex items-center justify-between"
                  >
                    <span>{item.name}</span>
                    <Play className="w-4 h-4 text-emerald-400" />
                  </button>
                ))}
              </div>

              {apiConsoleOutput && (
                <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 font-mono text-xs space-y-2">
                  <div className="flex justify-between text-slate-400">
                    <span>Response ({apiConsoleOutput.method} {apiConsoleOutput.endpoint})</span>
                    <span className={apiConsoleOutput.status < 400 ? 'text-emerald-400' : 'text-red-400'}>
                      Status: {apiConsoleOutput.status}
                    </span>
                  </div>
                  <pre className="text-cyan-300 overflow-x-auto p-2 bg-slate-900 rounded">
                    {JSON.stringify(apiConsoleOutput.response, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}

          {/* TAB 8: PYTHON UNITTEST SUITE */}
          {activeTab === 'tests' && (
            <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <Terminal className="w-5 h-5 text-emerald-400" />
                  Python `unittest` Suite Execution
                </h3>
                <button
                  onClick={runTests}
                  disabled={isRunningTests}
                  className="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded text-xs font-bold"
                >
                  {isRunningTests ? 'Running...' : 'Run Test Suite'}
                </button>
              </div>

              {testResult ? (
                testResult.error ? (
                  <div className="p-4 rounded-lg bg-red-950/60 border border-red-800 font-mono text-xs text-red-300 space-y-1">
                    <p className="font-bold">Test execution error: {testResult.error}</p>
                    {testResult.details && <p className="text-red-400">{testResult.details}</p>}
                  </div>
                ) : (
                  <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-slate-300 space-y-2">
                    <p className="text-emerald-400">$ python3 -m unittest discover -s tests</p>
                    <p>Tests Executed: {testResult.tests_run}</p>
                    <p className={testResult.success ? 'text-emerald-400 font-bold' : 'text-red-400 font-bold'}>
                      Passed: {testResult.passed} / {testResult.tests_run}
                    </p>
                    <p className={testResult.coverage ? 'text-emerald-400' : 'text-amber-400'}>
                      Code Coverage: {testResult.coverage || 'Unavailable (install python coverage package to measure)'}
                    </p>
                  </div>
                )
              ) : (
                <p className="text-xs text-slate-500">Running Python test suite...</p>
              )}
            </div>
          )}

          {/* TAB 9: DOCKER & CONFIG */}
          {activeTab === 'docker' && (
            <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Server className="w-5 h-5 text-cyan-400" />
                Docker Container Deployment Setup
              </h3>
              <p className="text-xs text-slate-400">Dockerfile &amp; docker-compose.yml configured in project root (verify on a host with Docker Engine installed).</p>
              <div className="p-4 rounded bg-slate-950 font-mono text-xs text-slate-300">
                docker-compose up -d --build
              </div>
            </div>
          )}

          {/* TAB 10: PROJECT ARCHITECTURE & DEMO GUIDE */}
          {activeTab === 'mentor' && (
            <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4 text-xs">
              <h3 className="text-lg font-bold text-white font-sans flex items-center gap-2">
                <BookOpen className="w-5 h-5 text-blue-400" />
                Project Architecture &amp; Technical Evaluation Guide
              </h3>
              <div className="p-4 rounded bg-slate-800/60 border border-slate-700 space-y-2">
                <h4 className="font-bold text-cyan-400 text-sm">How to demonstrate real-time ransomware detection:</h4>
                <ol className="list-decimal pl-4 space-y-1 text-slate-300">
                  <li>Navigate to <strong>Sandbox Simulator</strong> tab.</li>
                  <li>Click <strong>Entropy Spike (.locked)</strong>.</li>
                  <li>Observe real-time filesystem event stream and Shannon entropy calculation (&gt;7.9 bits/byte).</li>
                  <li>Watch Threat Score update from 0 to High/Critical (&gt;=70/100) via Express SSE stream.</li>
                  <li>Verify alert creation in <strong>Alerts</strong> tab &amp; incident details in <strong>Incidents</strong> tab.</li>
                  <li>Check <code>./quarantine</code> directory to inspect isolated evidence file copies (originals preserved).</li>
                </ol>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
