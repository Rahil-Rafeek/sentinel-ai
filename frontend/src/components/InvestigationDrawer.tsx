import React, { useState } from 'react';
import { ThreatEvent } from '../types';
import { motion, AnimatePresence } from 'framer-motion';
import { X, ShieldAlert, CheckCircle, ExternalLink, Download, FileText, Send } from 'lucide-react';

interface InvestigationDrawerProps {
  event: ThreatEvent | null;
  onClose: () => void;
  onUpdateStatus?: (eventId: string, newStatus: ThreatEvent['status'], notes?: string) => void;
}

export const InvestigationDrawer: React.FC<InvestigationDrawerProps> = ({
  event,
  onClose,
  onUpdateStatus,
}) => {
  const [currentStatus, setCurrentStatus] = useState<ThreatEvent['status']>(event?.status || 'Open');
  const [notes, setNotes] = useState<string>(event?.analystNotes || '');
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  if (!event) return null;

  const handleSave = () => {
    if (onUpdateStatus) {
      onUpdateStatus(event.id, currentStatus, notes);
    }
    setToastMessage('Incident state updated and committed to SOC audit trail!');
    setTimeout(() => setToastMessage(null), 3000);
  };

  const exportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(event, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `${event.id}_forensic_dossier.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex justify-end">
        {/* Backdrop overlay */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={onClose}
          className="fixed inset-0 bg-obsidian-950/70 backdrop-blur-sm"
        />

        {/* Slide-over Content Drawer */}
        <motion.div
          initial={{ x: '100%' }}
          animate={{ x: 0 }}
          exit={{ x: '100%' }}
          transition={{ type: 'spring', damping: 28, stiffness: 280 }}
          className="relative z-10 h-full w-full max-w-2xl overflow-y-auto border-l border-slate-800 bg-obsidian-900/98 p-6 shadow-2xl shadow-cyan-500/20"
        >
          {/* Header */}
          <div className="flex items-start justify-between border-b border-slate-800 pb-4">
            <div className="flex items-center gap-3">
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-red-950/60 border border-red-500/40 text-red-400">
                <ShieldAlert className="h-6 w-6" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="mono text-xs font-bold text-cyan-400">{event.id}</span>
                  <span className="rounded bg-red-950/80 border border-red-500/50 px-2 py-0.5 text-[10px] font-bold text-red-400 uppercase">
                    {event.severity} SEVERITY
                  </span>
                  <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] font-semibold text-slate-400">
                    SIMULATED
                  </span>
                </div>
                <h2 className="text-xl font-black text-white mt-1">{event.category}</h2>
              </div>
            </div>

            <button
              onClick={onClose}
              className="rounded-lg border border-slate-800 p-2 text-slate-400 hover:border-slate-700 hover:text-white"
            >
              <X className="h-5 w-5" />
            </button>
          </div>

          {/* Toast Notification */}
          {toastMessage && (
            <div className="mt-4 flex items-center gap-2 rounded-lg bg-emerald-950/60 border border-emerald-500/50 p-3 text-xs font-bold text-emerald-400">
              <CheckCircle className="h-4 w-4" />
              <span>{toastMessage}</span>
            </div>
          )}

          {/* MITRE ATT&CK Matrix Card */}
          <div className="mt-6 rounded-xl border border-violet-500/30 bg-violet-950/10 p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-violet-400 uppercase tracking-wider">
                MITRE ATT&CK MAPPING
              </span>
              <a
                href={`https://attack.mitre.org/techniques/${event.mitreId.replace('.', '/')}`}
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-1 text-[11px] font-bold text-violet-300 hover:underline"
              >
                <span>ATT&CK Spec</span>
                <ExternalLink className="h-3 w-3" />
              </a>
            </div>
            <div className="mt-2 flex items-center gap-3">
              <span className="mono rounded bg-violet-900/40 px-2 py-1 text-sm font-black text-violet-200 border border-violet-500/40">
                {event.mitreId}
              </span>
              <div>
                <div className="text-sm font-bold text-white">{event.mitreName}</div>
                <div className="text-xs text-slate-400">Tactic: {event.mitreTactic}</div>
              </div>
            </div>
          </div>

          {/* Network Flow Telemetry Matrix */}
          <div className="mt-6">
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2.5">
              FLOW METRICS & PACKET TELEMETRY
            </h3>
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="rounded-lg border border-slate-800 bg-obsidian-950 p-3">
                <span className="text-[10px] font-bold text-slate-400 uppercase">SOURCE ENDPOINT</span>
                <div className="mono text-sm font-bold text-cyan-400 mt-1">
                  {event.srcIp}:{event.srcPort}
                </div>
              </div>
              <div className="rounded-lg border border-slate-800 bg-obsidian-950 p-3">
                <span className="text-[10px] font-bold text-slate-400 uppercase">TARGET INFRASTRUCTURE</span>
                <div className="mono text-sm font-bold text-violet-400 mt-1">
                  {event.dstIp}:{event.dstPort}
                </div>
              </div>
              <div className="rounded-lg border border-slate-800 bg-obsidian-950 p-3">
                <span className="text-[10px] font-bold text-slate-400 uppercase">PROTOCOL & DURATION</span>
                <div className="mono text-sm font-bold text-slate-200 mt-1">
                  {event.protocol} ({event.durationSec}s)
                </div>
              </div>
              <div className="rounded-lg border border-slate-800 bg-obsidian-950 p-3">
                <span className="text-[10px] font-bold text-slate-400 uppercase">PAYLOAD & PACKETS</span>
                <div className="mono text-sm font-bold text-slate-200 mt-1">
                  {event.bytesSent.toLocaleString()}B / {event.packetsSent + event.packetsReceived} pkts
                </div>
              </div>
            </div>
          </div>

          {/* Evidence Narrative */}
          <div className="mt-6 rounded-xl border-l-4 border-l-red-500 border border-slate-800 bg-obsidian-950/80 p-4">
            <span className="text-xs font-bold text-red-400 uppercase tracking-wider">
              CORROBORATED DETECTION EVIDENCE
            </span>
            <p className="mt-2 text-xs text-slate-200 leading-relaxed">{event.evidence}</p>
          </div>

          {/* Defensive Mitigation Playbook */}
          <div className="mt-4 rounded-xl border-l-4 border-l-cyan-400 border border-slate-800 bg-obsidian-950/80 p-4">
            <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider">
              TACTICAL MITIGATION PLAYBOOK
            </span>
            <p className="mt-2 text-xs text-slate-200 leading-relaxed">{event.recommendedAction}</p>
          </div>

          {/* Incident Triage & Analyst Response Controls */}
          <div className="mt-6 border-t border-slate-800 pt-5">
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">
              INCIDENT RESPONSE STATUS & ANALYST LOG
            </h3>
            <div className="space-y-3">
              <div>
                <label className="text-xs font-semibold text-slate-400 block mb-1">Lifecycle State</label>
                <select
                  value={currentStatus}
                  onChange={(e) => setCurrentStatus(e.target.value as ThreatEvent['status'])}
                  className="w-full rounded-lg border border-slate-700 bg-obsidian-950 p-2.5 text-xs font-bold text-white focus:border-cyan-400 focus:outline-none"
                >
                  <option value="Open">Open — Pending Triage</option>
                  <option value="Investigating">Investigating — Active Forensic Capture</option>
                  <option value="Resolved">Resolved — Remediation Verified</option>
                  <option value="False Positive">False Positive — Rule Baseline Tuned</option>
                </select>
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-400 block mb-1">Analyst Notes</label>
                <textarea
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="Record root cause findings, firewall rule IDs, or quarantine tickets..."
                  rows={3}
                  className="w-full rounded-lg border border-slate-700 bg-obsidian-950 p-2.5 text-xs text-slate-200 focus:border-cyan-400 focus:outline-none"
                />
              </div>

              <div className="flex items-center gap-3 pt-2">
                <button
                  onClick={handleSave}
                  className="flex-1 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 px-4 py-2 text-xs font-bold text-obsidian-950 shadow-lg shadow-cyan-500/20 hover:brightness-110 flex items-center justify-center gap-2"
                >
                  <Send className="h-3.5 w-3.5" />
                  <span>Update Incident Status</span>
                </button>

                <button
                  onClick={exportJson}
                  className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-xs font-bold text-slate-300 hover:bg-slate-700 flex items-center gap-2"
                >
                  <Download className="h-3.5 w-3.5" />
                  <span>Export JSON</span>
                </button>
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
