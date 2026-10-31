import React from 'react';
import { ThreatEvent, SystemTelemetry } from '../types';
import { HeroRadar } from '../components/HeroRadar';
import { FloatingTelemetryBar } from '../components/FloatingTelemetryBar';
import { EventRibbon } from '../components/EventRibbon';
import { ReplayControlBar } from '../components/ReplayControlBar';
import { motion } from 'framer-motion';
import { ShieldAlert, Zap, Radio, ArrowUpRight, Compass } from 'lucide-react';
import { ReplayState } from '../services/api';

interface CommandCenterProps {
  events: ThreatEvent[];
  telemetry: SystemTelemetry;
  onSelectEvent: (event: ThreatEvent) => void;
  selectedEventId?: string;
  onNavigateToTab: (tabId: string) => void;
  replayState?: ReplayState;
  onStartReplay?: () => void;
  onPauseReplay?: () => void;
  onResumeReplay?: () => void;
  onStopReplay?: () => void;
  onSetSpeed?: (speed: number) => void;
}

export const CommandCenter: React.FC<CommandCenterProps> = ({
  events,
  telemetry,
  onSelectEvent,
  selectedEventId,
  onNavigateToTab,
  replayState,
  onStartReplay,
  onPauseReplay,
  onResumeReplay,
  onStopReplay,
  onSetSpeed,
}) => {
  const criticalThreats = events.filter((e) => e.severity === 'Critical' || e.severity === 'High');

  return (
    <div className="space-y-8 pb-12">
      {/* Cinematic Hero Section */}
      <section className="relative overflow-hidden rounded-3xl border border-slate-800 bg-gradient-to-b from-obsidian-900/90 via-obsidian-950/90 to-obsidian-950 p-8 sm:p-12 shadow-2xl backdrop-blur-2xl">
        {/* Fine Animated Cyber Grid Background */}
        <div className="pointer-events-none absolute inset-0 bg-cyber-grid opacity-30"></div>
        <div className="pointer-events-none absolute -right-24 -top-24 h-96 w-96 rounded-full bg-cyan-500/10 blur-3xl"></div>
        <div className="pointer-events-none absolute -left-24 bottom-0 h-96 w-96 rounded-full bg-violet-600/10 blur-3xl"></div>

        <div className="relative z-10 grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
          {/* Left Column: Oversized Editorial Typography & Floating Posture HUD */}
          <div className="lg:col-span-5 space-y-6">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
              className="inline-flex items-center gap-2 rounded-full border border-cyan-500/30 bg-cyan-950/40 px-3.5 py-1 text-xs font-bold text-cyan-300 backdrop-blur-md"
            >
              <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse"></span>
              <span>AUTONOMOUS THREAT SURVEILLANCE ACTIVE</span>
            </motion.div>

            <motion.h1
              initial={{ opacity: 0, y: 25 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.1 }}
              className="text-4xl sm:text-5xl lg:text-6xl font-black tracking-tight text-white uppercase leading-[1.08]"
            >
              THE NETWORK <br />
              <span className="bg-gradient-to-r from-white via-cyan-200 to-cyan-400 bg-clip-text text-transparent">
                NEVER SLEEPS.
              </span>
            </motion.h1>

            <motion.p
              initial={{ opacity: 0, y: 25 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.2 }}
              className="text-sm text-slate-300 leading-relaxed font-medium max-w-md"
            >
              Continuous dual-inference security intelligence orchestrating Random Forest and rule-based heuristic engines. 
              Analyzing live ingress telemetry against the MITRE ATT&CK framework with sub-5ms classification latency.
            </motion.p>

            {/* Quick Action Pill Buttons */}
            <motion.div
              initial={{ opacity: 0, y: 25 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.3 }}
              className="flex items-center gap-3 pt-2"
            >
              <button
                onClick={() => onNavigateToTab('intelligence')}
                className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 px-5 py-2.5 text-xs font-bold text-obsidian-950 shadow-lg shadow-cyan-500/25 transition-all hover:brightness-110 active:scale-98"
              >
                <span>Launch Attack Topology</span>
                <ArrowUpRight className="h-4 w-4" />
              </button>

              <button
                onClick={() => onNavigateToTab('alerts')}
                className="flex items-center gap-2 rounded-xl border border-slate-700 bg-obsidian-900 px-5 py-2.5 text-xs font-bold text-slate-200 transition-all hover:border-slate-600 hover:bg-slate-800 active:scale-98"
              >
                <span>Active Alerts ({criticalThreats.length})</span>
              </button>
            </motion.div>
          </div>

          {/* Right Column: Signature Threat Radar Centerpiece */}
          <div className="lg:col-span-7 flex justify-center">
            <HeroRadar
              events={events}
              onSelectEvent={onSelectEvent}
              selectedEventId={selectedEventId}
            />
          </div>
        </div>
      </section>

      {/* Dataset Replay Controls (When available) */}
      {replayState && onStartReplay && onPauseReplay && onResumeReplay && onStopReplay && onSetSpeed && (
        <ReplayControlBar
          replayState={replayState}
          onStartReplay={onStartReplay}
          onPauseReplay={onPauseReplay}
          onResumeReplay={onResumeReplay}
          onStopReplay={onStopReplay}
          onSetSpeed={onSetSpeed}
        />
      )}

      {/* Floating Telemetry Ribbons */}
      <FloatingTelemetryBar telemetry={telemetry} />

      {/* Live Threat Event Stream Section */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-black text-white uppercase tracking-wider">
                LIVE ADVERSARY INCIDENT STREAM
              </h2>
              <span className="rounded bg-red-950/80 border border-red-500/40 px-2 py-0.5 text-[10px] font-bold text-red-400">
                ACTIVE INGESTION
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Select any threat ribbon to expand full telemetry, corroborated evidence, and MITRE playbooks.
            </p>
          </div>

          <button
            onClick={() => onNavigateToTab('explorer')}
            className="flex items-center gap-1.5 text-xs font-bold text-cyan-400 hover:text-cyan-300 hover:underline"
          >
            <span>View All {events.length} Telemetry Events</span>
            <ArrowUpRight className="h-3.5 w-3.5" />
          </button>
        </div>

        <div className="space-y-2.5">
          {events.length === 0 ? (
            <div className="rounded-xl border border-slate-800 bg-obsidian-900/40 p-8 text-center text-xs text-slate-400">
              No threat events recorded for the active dataset. Upload a dataset or inject an attack vector to begin.
            </div>
          ) : (
            (criticalThreats.length > 0 ? criticalThreats : events).slice(0, 6).map((event) => (
              <EventRibbon
                key={event.id}
                event={event}
                onSelect={onSelectEvent}
                isSelected={selectedEventId === event.id}
              />
            ))
          )}
        </div>
      </section>
    </div>
  );
};
