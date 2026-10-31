import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { ThreatEvent, AlertStatus, SystemTelemetry } from './types';
import { MOCK_THREAT_EVENTS, INITIAL_TELEMETRY } from './data/mockData';
import { Navbar } from './components/Navbar';
import { IntelligenceMarquee } from './components/IntelligenceMarquee';
import { InvestigationDrawer } from './components/InvestigationDrawer';
import { DatasetUploadModal } from './components/DatasetUploadModal';
import { CommandCenter } from './pages/CommandCenter';
import { ThreatIntelligence } from './pages/ThreatIntelligence';
import { ThreatExplorer } from './pages/ThreatExplorer';
import { SecurityAnalytics } from './pages/SecurityAnalytics';
import { DetectionPlayground } from './pages/DetectionPlayground';
import { AlertCenter } from './pages/AlertCenter';
import { SystemMonitor } from './pages/SystemMonitor';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  api, 
  DatasetItem, 
  SummaryMetrics, 
  TimeSeriesPoint, 
  TopPortItem, 
  MLMetricsResponse, 
  ReplayState, 
  createMonitoringWebSocket 
} from './services/api';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>('command');
  
  // Datasets state
  const [datasets, setDatasets] = useState<DatasetItem[]>([]);
  const [activeDatasetId, setActiveDatasetId] = useState<string | null>(null);
  const [isUploadModalOpen, setIsUploadModalOpen] = useState(false);

  // Events & Analytics state
  const [events, setEvents] = useState<ThreatEvent[]>(MOCK_THREAT_EVENTS);
  const [summary, setSummary] = useState<SummaryMetrics | null>(null);
  const [timeSeriesData, setTimeSeriesData] = useState<TimeSeriesPoint[]>([]);
  const [topPortsData, setTopPortsData] = useState<TopPortItem[]>([]);
  const [mlMetrics, setMlMetrics] = useState<MLMetricsResponse | null>(null);

  const [selectedEventId, setSelectedEventId] = useState<string | undefined>(MOCK_THREAT_EVENTS[0]?.id);
  const [activeDrawerEvent, setActiveDrawerEvent] = useState<ThreatEvent | null>(null);

  // Replay State
  const [replayState, setReplayState] = useState<ReplayState>({
    session_id: null,
    dataset_id: null,
    status: 'stopped',
    speed: 1.0,
    current_index: 0,
    total_events: 0,
    findings_count: 0
  });

  // Load datasets and active data from backend
  const loadActiveData = useCallback(async (targetDatasetId?: string) => {
    try {
      const dsList = await api.listDatasets();
      setDatasets(dsList);

      let currentId = targetDatasetId;
      if (!currentId) {
        const activeDs = await api.getActiveDataset().catch(() => null);
        currentId = activeDs?.id || dsList[0]?.id;
      }

      if (currentId) {
        setActiveDatasetId(currentId);

        // Fetch events, summary, time series, top ports, and ML metrics in parallel
        const [eventsRes, summaryRes, tsRes, portsRes, mlRes] = await Promise.all([
          api.fetchEvents({ dataset_id: currentId, page_size: 100 }).catch(() => null),
          api.fetchSummary(currentId).catch(() => null),
          api.fetchTimeSeries(currentId).catch(() => []),
          api.fetchTopPorts(currentId).catch(() => []),
          api.fetchMLMetrics(currentId).catch(() => null),
        ]);

        if (eventsRes && eventsRes.events && eventsRes.events.length > 0) {
          setEvents(eventsRes.events);
          setSelectedEventId(eventsRes.events[0]?.id);
        }
        if (summaryRes) setSummary(summaryRes);
        if (tsRes) setTimeSeriesData(tsRes);
        if (portsRes) setTopPortsData(portsRes);
        if (mlRes) setMlMetrics(mlRes);
      }
    } catch (err) {
      console.warn('[SENTINEL AI] Backend offline or initializing, falling back to local benchmark data.');
    }
  }, []);

  useEffect(() => {
    loadActiveData();

    // Subscribe to live WebSocket feed
    const cleanupWs = createMonitoringWebSocket(
      (msg) => {
        if (msg.type === 'REPLAY_STATE_CHANGE' || msg.type === 'REPLAY_COMPLETED') {
          if (msg.state) setReplayState(msg.state);
        } else if (msg.type === 'REPLAY_EVENT') {
          if (msg.event) {
            setEvents((prev) => [msg.event, ...prev.slice(0, 99)]);
            if (msg.progress) {
              setReplayState((prev) => ({
                ...prev,
                current_index: msg.progress.current,
                total_events: msg.progress.total,
                status: 'playing'
              }));
            }
          }
        } else if (msg.type === 'THREAT_INJECTED' || msg.type === 'TELEMETRY_EVENT') {
          if (msg.event) {
            setEvents((prev) => [msg.event, ...prev]);
            setSelectedEventId(msg.event.id);
          }
        }
      },
      (connected) => {
        // connection state
      }
    );

    return () => {
      cleanupWs();
    };
  }, [loadActiveData]);

  // Derived telemetry metrics
  const telemetry: SystemTelemetry = useMemo(() => {
    const criticalCount = summary?.critical_count ?? events.filter((e) => e.severity === 'Critical').length;
    const highCount = summary?.high_count ?? events.filter((e) => e.severity === 'High').length;
    return {
      ...INITIAL_TELEMETRY,
      totalThreats: summary?.threats_count ?? events.length,
      criticalCount,
      highCount,
      threatScore: summary?.threat_score ?? Math.min(99, 45 + criticalCount * 4 + highCount * 2),
      postureLevel: (summary?.posture_level as any) || (criticalCount > 5 ? 'DEFCON 2' : 'DEFCON 3'),
    };
  }, [events, summary]);

  // Event Handlers
  const handleSelectEvent = (event: ThreatEvent) => {
    setSelectedEventId(event.id);
    setActiveDrawerEvent(event);
  };

  const handleOpenDrawer = (event: ThreatEvent) => {
    setActiveDrawerEvent(event);
  };

  const handleCloseDrawer = () => {
    setActiveDrawerEvent(null);
  };

  const handleUpdateStatus = async (eventId: string, newStatus: AlertStatus, notes?: string) => {
    // 1. Optimistic local update
    setEvents((prev) =>
      prev.map((e) => {
        if (e.id === eventId) {
          return {
            ...e,
            status: newStatus,
            analystNotes: notes !== undefined ? notes : e.analystNotes,
          };
        }
        return e;
      })
    );

    if (activeDrawerEvent && activeDrawerEvent.id === eventId) {
      setActiveDrawerEvent((prev) =>
        prev
          ? {
              ...prev,
              status: newStatus,
              analystNotes: notes !== undefined ? notes : prev.analystNotes,
            }
          : null
      );
    }

    // 2. Persist to SQLite backend if corresponding alert exists
    try {
      const altId = `ALT-${eventId}`;
      await api.updateAlertStatus(altId, newStatus, notes);
    } catch {
      // ignore
    }
  };

  const handleInjectThreat = async (newEvent: ThreatEvent) => {
    // Optimistic local prepend
    setEvents((prev) => [newEvent, ...prev]);
    setSelectedEventId(newEvent.id);

    // Persist to backend database and broadcast over WebSocket
    try {
      await api.injectThreat(newEvent);
    } catch {
      // fallback
    }
  };

  const handleSelectDataset = async (datasetId: string) => {
    try {
      await api.activateDataset(datasetId);
      await loadActiveData(datasetId);
    } catch (err) {
      console.error('Failed to activate dataset:', err);
    }
  };

  const handleDatasetActivated = (datasetId: string) => {
    loadActiveData(datasetId);
  };

  // Replay handlers
  const handleStartReplay = async () => {
    try {
      await api.startReplay(activeDatasetId || undefined, replayState.speed);
    } catch (err) {
      console.error('Failed to start replay:', err);
    }
  };

  const handlePauseReplay = async () => {
    try {
      await api.pauseReplay();
    } catch (err) {
      console.error('Failed to pause replay:', err);
    }
  };

  const handleResumeReplay = async () => {
    try {
      await api.resumeReplay();
    } catch (err) {
      console.error('Failed to resume replay:', err);
    }
  };

  const handleStopReplay = async () => {
    try {
      await api.stopReplay();
    } catch (err) {
      console.error('Failed to stop replay:', err);
    }
  };

  const handleSetSpeed = async (speed: number) => {
    try {
      await api.setReplaySpeed(speed);
      setReplayState(prev => ({ ...prev, speed }));
    } catch (err) {
      console.error('Failed to set replay speed:', err);
    }
  };

  return (
    <div className="min-h-screen bg-obsidian-950 text-slate-100 flex flex-col antialiased selection:bg-cyan-500 selection:text-obsidian-950 font-sans">
      {/* Top Glassmorphic Navigation Bar */}
      <Navbar 
        activeTab={activeTab} 
        setActiveTab={setActiveTab}
        datasets={datasets}
        activeDatasetId={activeDatasetId}
        onSelectDataset={handleSelectDataset}
        onOpenUploadModal={() => setIsUploadModalOpen(true)}
        criticalCount={telemetry.criticalCount}
        postureLevel={telemetry.postureLevel}
      />

      {/* Real-Time Continuous Intelligence Marquee */}
      <IntelligenceMarquee />

      {/* Primary Page Content Wrapper */}
      <main className="flex-1 mx-auto w-full max-w-7xl px-4 sm:px-6 lg:px-8 pt-6">
        <AnimatePresence mode="wait">
          <motion.div
            key={activeTab}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -12 }}
            transition={{ duration: 0.22, ease: 'easeOut' }}
          >
            {activeTab === 'command' && (
              <CommandCenter
                events={events}
                telemetry={telemetry}
                onSelectEvent={handleSelectEvent}
                selectedEventId={selectedEventId}
                onNavigateToTab={setActiveTab}
                replayState={replayState}
                onStartReplay={handleStartReplay}
                onPauseReplay={handlePauseReplay}
                onResumeReplay={handleResumeReplay}
                onStopReplay={handleStopReplay}
                onSetSpeed={handleSetSpeed}
              />
            )}

            {activeTab === 'intelligence' && <ThreatIntelligence />}

            {activeTab === 'explorer' && (
              <ThreatExplorer
                events={events}
                onSelectEvent={handleSelectEvent}
                selectedEventId={selectedEventId}
              />
            )}

            {activeTab === 'analytics' && (
              <SecurityAnalytics 
                events={events}
                timeSeriesData={timeSeriesData}
                topPortsData={topPortsData}
                mlMetrics={mlMetrics}
              />
            )}

            {activeTab === 'playground' && (
              <DetectionPlayground
                onInjectThreat={handleInjectThreat}
                onOpenDrawer={handleOpenDrawer}
              />
            )}

            {activeTab === 'alerts' && (
              <AlertCenter
                events={events}
                onOpenDrawer={handleOpenDrawer}
                onUpdateStatus={handleUpdateStatus}
              />
            )}

            {activeTab === 'monitor' && <SystemMonitor />}
          </motion.div>
        </AnimatePresence>
      </main>

      {/* Dataset Upload Modal */}
      <DatasetUploadModal
        isOpen={isUploadModalOpen}
        onClose={() => setIsUploadModalOpen(false)}
        onDatasetActivated={handleDatasetActivated}
      />

      {/* Forensic Investigation Slide-Over Drawer */}
      <InvestigationDrawer
        event={activeDrawerEvent}
        onClose={handleCloseDrawer}
        onUpdateStatus={handleUpdateStatus}
      />

      {/* Global Cinematic Footer */}
      <footer className="mt-auto border-t border-slate-900 bg-obsidian-950/90 py-6 text-xs text-slate-400">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-6 w-6 items-center justify-center rounded bg-cyan-950/60 border border-cyan-500/40 text-cyan-400 font-bold text-[10px]">
              S
            </div>
            <div>
              <span className="font-bold text-white">SENTINEL AI</span> — Intelligent Cybersecurity Threat Detection & Monitoring System
            </div>
          </div>

          <div className="flex items-center gap-4 text-[11px]">
            <span className="mono rounded bg-slate-900 px-2 py-0.5 border border-slate-800 text-slate-400">
              FASTAPI REST ENGINE + SQLITE ORM
            </span>
            <span>MITRE ATT&CK v14.1</span>
            <span>Dual Scikit-Learn Ensemble</span>
            <span>WebSocket Live Stream</span>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default App;
