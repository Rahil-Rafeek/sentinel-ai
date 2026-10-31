import { ThreatEvent, AlertStatus, Severity, ThreatCategory } from '../types';

const getApiBase = () => {
  if (typeof window === 'undefined') return 'http://localhost:8000/api/v1';
  // Use relative '/api/v1' to route through Vite proxy on any device (iOS, Mac, Windows)
  return '/api/v1';
};

const getWsBase = () => {
  if (typeof window === 'undefined') return 'ws://localhost:8000/api/v1/monitoring/ws';
  const host = window.location.host; // includes port if present (e.g., 192.168.1.56:5173 or localhost:5173)
  const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${wsProto}//${host}/api/v1/monitoring/ws`;
};

export const API_BASE = getApiBase();
export const WS_BASE = getWsBase();

export interface DatasetItem {
  id: string;
  filename: string;
  file_size_bytes: number;
  row_count: number;
  column_count: number;
  compatibility_status: string;
  compatibility_reasons: string[];
  is_active: boolean;
  created_at: string;
}

export interface ColumnMappingSuggestion {
  target_field: string;
  source_column: string | null;
  confidence: number;
  explanation: string;
  required_for: string[];
}

export interface DataProfile {
  total_rows: number;
  total_columns: number;
  duplicate_rows: number;
  column_types: Record<string, string>;
  missing_values: Record<string, number>;
  sample_rows: Record<string, any>[];
}

export interface DatasetUploadResponse {
  dataset_id: string;
  filename: string;
  row_count: number;
  column_count: number;
  compatibility_status: string;
  compatibility_reasons: string[];
  suggested_mapping: Record<string, string | null>;
  mapping_details: ColumnMappingSuggestion[];
  data_profile: DataProfile;
}

export interface SummaryMetrics {
  total_events: number;
  threats_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  benign_count: number;
  threat_score: number;
  posture_level: string;
  active_dataset_id: string | null;
  active_dataset_name: string | null;
  dataset_compatibility: string | null;
}

export interface DistributionItem {
  name: string;
  count: number;
  percentage: number;
  color?: string;
}

export interface TimeSeriesPoint {
  timestamp: string;
  packet_rate: number;
  threat_count: number;
  critical_count: number;
}

export interface TopPortItem {
  port: number;
  count: number;
  service: string;
  threat_ratio: number;
}

export interface MLMetricsResponse {
  is_available: boolean;
  is_supervised: boolean;
  model_name: string;
  accuracy?: number;
  precision?: number;
  recall?: number;
  f1_score?: number;
  roc_auc?: number;
  confusion_matrix?: number[][];
  class_labels?: string[];
  anomaly_count?: number;
  anomaly_ratio?: number;
  notes?: string;
}

export interface SystemHealth {
  status: string;
  uptime_sec: number;
  subsystems: {
    api_engine: { status: string; version: string };
    database_sqlite: { status: string; error?: string | null };
    uploads_storage: { status: string };
    model_artifacts: { status: string };
    detection_workers: { status: string; active_detectors: number };
  };
}

export interface SystemMetrics {
  events_per_sec: number;
  mean_inference_latency_ms: number;
  database_size_bytes: number;
  database_size_mb: number;
  total_datasets: number;
  total_events_indexed: number;
  total_alerts: number;
  open_alerts: number;
  completed_analysis_jobs: number;
  cache_hit_rate: number;
  ring_buffer_usage_pct: number;
}

export interface ReplayState {
  session_id: string | null;
  dataset_id: string | null;
  status: 'stopped' | 'playing' | 'paused' | 'completed';
  speed: number;
  current_index: number;
  total_events: number;
  findings_count: number;
}

// --- API Methods ---

export const api = {
  // Datasets
  async listDatasets(): Promise<DatasetItem[]> {
    const res = await fetch(`${API_BASE}/datasets/`);
    if (!res.ok) throw new Error('Failed to fetch datasets');
    return res.json();
  },

  async getActiveDataset(): Promise<any> {
    const res = await fetch(`${API_BASE}/datasets/active`);
    if (!res.ok) throw new Error('Failed to fetch active dataset');
    return res.json();
  },

  async uploadDataset(file: File): Promise<DatasetUploadResponse> {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE}/datasets/upload`, {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Upload failed' }));
      throw new Error(err.detail || 'Upload failed');
    }
    return res.json();
  },

  async confirmMapping(datasetId: string, mapping: Record<string, string>): Promise<any> {
    const res = await fetch(`${API_BASE}/datasets/${datasetId}/mapping`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mapping }),
    });
    if (!res.ok) throw new Error('Failed to confirm mapping');
    return res.json();
  },

  async activateDataset(datasetId: string): Promise<any> {
    const res = await fetch(`${API_BASE}/datasets/${datasetId}/activate`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error('Failed to activate dataset');
    return res.json();
  },

  async deleteDataset(datasetId: string): Promise<any> {
    const res = await fetch(`${API_BASE}/datasets/${datasetId}`, {
      method: 'DELETE',
    });
    if (!res.ok) throw new Error('Failed to delete dataset');
    return res.json();
  },

  // Analysis
  async startAnalysis(datasetId: string, runMl = true): Promise<any> {
    const res = await fetch(`${API_BASE}/analysis/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dataset_id: datasetId, run_ml: runMl }),
    });
    if (!res.ok) throw new Error('Failed to start analysis');
    return res.json();
  },

  async getJobStatus(jobId: string): Promise<any> {
    const res = await fetch(`${API_BASE}/analysis/${jobId}/status`);
    if (!res.ok) throw new Error('Failed to fetch job status');
    return res.json();
  },

  // Events
  async fetchEvents(params?: {
    dataset_id?: string;
    category?: string;
    severity?: string;
    search?: string;
    sort_by?: string;
    page?: number;
    page_size?: number;
  }): Promise<{ total: number; page: number; page_size: number; total_pages: number; events: ThreatEvent[] }> {
    const searchParams = new URLSearchParams();
    if (params?.dataset_id) searchParams.append('dataset_id', params.dataset_id);
    if (params?.category) searchParams.append('category', params.category);
    if (params?.severity) searchParams.append('severity', params.severity);
    if (params?.search) searchParams.append('search', params.search);
    if (params?.sort_by) searchParams.append('sort_by', params.sort_by);
    if (params?.page) searchParams.append('page', params.page.toString());
    if (params?.page_size) searchParams.append('page_size', params.page_size.toString());

    const res = await fetch(`${API_BASE}/events/?${searchParams.toString()}`);
    if (!res.ok) throw new Error('Failed to fetch events');
    const data = await res.json();
    
    // Map backend snake_case to frontend ThreatEvent camelCase
    const mappedEvents: ThreatEvent[] = data.events.map((e: any) => ({
      id: e.id,
      timestamp: e.timestamp,
      category: e.category,
      severity: e.severity,
      confidence: e.confidence,
      srcIp: e.src_ip || '192.168.1.100',
      srcPort: e.src_port || 52000,
      dstIp: e.dst_ip || '10.0.0.12',
      dstPort: e.dst_port || 80,
      protocol: e.protocol || 'TCP',
      durationSec: e.duration_sec || 0.5,
      bytesSent: e.bytes_sent || 1024,
      bytesReceived: e.bytes_received || 512,
      packetsSent: e.packets_sent || 10,
      packetsReceived: e.packets_received || 4,
      detectionMethod: e.detection_method,
      evidence: e.evidence,
      recommendedAction: e.recommended_action,
      status: 'Open',
      mitreId: e.mitre_id || 'T1000',
      mitreName: e.mitre_name || 'Generic Threat Vector',
      mitreTactic: e.mitre_tactic || 'Reconnaissance',
      radarAngle: e.radar_angle,
      radarRadius: e.radar_radius,
    }));

    return { ...data, events: mappedEvents };
  },

  // Alerts
  async fetchAlerts(params?: {
    dataset_id?: string;
    status?: string;
    severity?: string;
    category?: string;
  }): Promise<any[]> {
    const searchParams = new URLSearchParams();
    if (params?.dataset_id) searchParams.append('dataset_id', params.dataset_id);
    if (params?.status) searchParams.append('status', params.status);
    if (params?.severity) searchParams.append('severity', params.severity);
    if (params?.category) searchParams.append('category', params.category);

    const res = await fetch(`${API_BASE}/alerts/?${searchParams.toString()}`);
    if (!res.ok) throw new Error('Failed to fetch alerts');
    return res.json();
  },

  async updateAlertStatus(alertId: string, status: AlertStatus, notes?: string): Promise<any> {
    const res = await fetch(`${API_BASE}/alerts/${alertId}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, notes }),
    });
    if (!res.ok) throw new Error('Failed to update alert status');
    return res.json();
  },

  getAlertsCsvUrl(datasetId?: string): string {
    return `${API_BASE}/alerts/export/csv${datasetId ? `?dataset_id=${datasetId}` : ''}`;
  },

  // Analytics
  async fetchSummary(datasetId?: string): Promise<SummaryMetrics> {
    const url = `${API_BASE}/analytics/summary${datasetId ? `?dataset_id=${datasetId}` : ''}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to fetch summary metrics');
    return res.json();
  },

  async fetchCategories(datasetId?: string): Promise<DistributionItem[]> {
    const url = `${API_BASE}/analytics/categories${datasetId ? `?dataset_id=${datasetId}` : ''}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to fetch category distribution');
    return res.json();
  },

  async fetchSeverities(datasetId?: string): Promise<DistributionItem[]> {
    const url = `${API_BASE}/analytics/severities${datasetId ? `?dataset_id=${datasetId}` : ''}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to fetch severity distribution');
    return res.json();
  },

  async fetchTimeSeries(datasetId?: string): Promise<TimeSeriesPoint[]> {
    const url = `${API_BASE}/analytics/time-series${datasetId ? `?dataset_id=${datasetId}` : ''}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to fetch time series');
    return res.json();
  },

  async fetchTopPorts(datasetId?: string): Promise<TopPortItem[]> {
    const url = `${API_BASE}/analytics/top-ports${datasetId ? `?dataset_id=${datasetId}` : ''}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to fetch top ports');
    return res.json();
  },

  async fetchMLMetrics(datasetId?: string): Promise<MLMetricsResponse> {
    const url = `${API_BASE}/analytics/model-metrics${datasetId ? `?dataset_id=${datasetId}` : ''}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to fetch ML metrics');
    return res.json();
  },

  // Detection Playground
  async evaluatePlayground(params: any): Promise<any> {
    const res = await fetch(`${API_BASE}/detect/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    });
    if (!res.ok) throw new Error('Failed to evaluate threat parameters');
    return res.json();
  },

  async injectThreat(event: ThreatEvent): Promise<any> {
    const res = await fetch(`${API_BASE}/detect/inject`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        category: event.category,
        severity: event.severity,
        confidence: event.confidence,
        src_ip: event.srcIp,
        src_port: event.srcPort,
        dst_ip: event.dstIp,
        dst_port: event.dstPort,
        protocol: event.protocol,
        evidence: event.evidence,
        recommended_action: event.recommendedAction,
        mitre_id: event.mitreId,
        mitre_name: event.mitreName,
        mitre_tactic: event.mitreTactic,
      }),
    });
    if (!res.ok) throw new Error('Failed to inject threat');
    return res.json();
  },

  // Monitoring & Replay
  async fetchMonitoringStatus(): Promise<any> {
    const res = await fetch(`${API_BASE}/monitoring/status`);
    if (!res.ok) throw new Error('Failed to fetch monitoring status');
    return res.json();
  },

  async startReplay(datasetId?: string, speed = 1.0): Promise<any> {
    const url = `${API_BASE}/monitoring/replay/start${datasetId ? `?dataset_id=${datasetId}` : ''}`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'start', speed }),
    });
    if (!res.ok) throw new Error('Failed to start replay');
    return res.json();
  },

  async pauseReplay(): Promise<any> {
    const res = await fetch(`${API_BASE}/monitoring/replay/pause`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to pause replay');
    return res.json();
  },

  async resumeReplay(): Promise<any> {
    const res = await fetch(`${API_BASE}/monitoring/replay/resume`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to resume replay');
    return res.json();
  },

  async stopReplay(): Promise<any> {
    const res = await fetch(`${API_BASE}/monitoring/replay/stop`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to stop replay');
    return res.json();
  },

  async setReplaySpeed(speed: number): Promise<any> {
    const res = await fetch(`${API_BASE}/monitoring/replay/speed?speed=${speed}`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to set replay speed');
    return res.json();
  },

  // System
  async fetchSystemHealth(): Promise<SystemHealth> {
    const res = await fetch(`${API_BASE}/system/health`);
    if (!res.ok) throw new Error('Failed to fetch system health');
    return res.json();
  },

  async fetchSystemMetrics(): Promise<SystemMetrics> {
    const res = await fetch(`${API_BASE}/system/metrics`);
    if (!res.ok) throw new Error('Failed to fetch system metrics');
    return res.json();
  },
};

// --- WebSocket Connection Helper with Heartbeat & Auto-Reconnect ---

export function createMonitoringWebSocket(
  onMessage: (msg: any) => void,
  onStatusChange?: (connected: boolean) => void
): () => void {
  let ws: WebSocket | null = null;
  let isClosed = false;
  let pingInterval: any = null;

  function connect() {
    if (isClosed) return;
    try {
      ws = new WebSocket(WS_BASE);

      ws.onopen = () => {
        if (onStatusChange) onStatusChange(true);
        pingInterval = setInterval(() => {
          if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send('ping');
          }
        }, 15000);
      };

      ws.onmessage = (event) => {
        if (event.data === 'pong') return;
        try {
          const parsed = JSON.parse(event.data);
          onMessage(parsed);
        } catch (e) {
          // ignore non-json
        }
      };

      ws.onclose = () => {
        if (onStatusChange) onStatusChange(false);
        if (pingInterval) clearInterval(pingInterval);
        if (!isClosed) {
          setTimeout(connect, 3000); // Reconnect after 3s
        }
      };

      ws.onerror = () => {
        ws?.close();
      };
    } catch (e) {
      if (!isClosed) setTimeout(connect, 3000);
    }
  }

  connect();

  return () => {
    isClosed = true;
    if (pingInterval) clearInterval(pingInterval);
    ws?.close();
  };
}
