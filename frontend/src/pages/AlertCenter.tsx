import React, { useState, useMemo } from 'react';
import { ThreatEvent, AlertStatus, Severity, ThreatCategory } from '../types';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  ShieldAlert, 
  Search, 
  Filter, 
  Download, 
  CheckCircle, 
  Clock, 
  AlertTriangle, 
  Ban, 
  ExternalLink, 
  FileSpreadsheet, 
  Layers,
  ArrowUpDown,
  FileCode,
  ShieldCheck,
  UserCheck
} from 'lucide-react';

interface AlertCenterProps {
  events: ThreatEvent[];
  onOpenDrawer: (event: ThreatEvent) => void;
  onUpdateStatus: (eventId: string, newStatus: AlertStatus, notes?: string) => void;
}

export const AlertCenter: React.FC<AlertCenterProps> = ({
  events,
  onOpenDrawer,
  onUpdateStatus,
}) => {
  const [selectedStatus, setSelectedStatus] = useState<string>('All');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('All');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [sortField, setSortField] = useState<'timestamp' | 'confidence' | 'severity'>('timestamp');
  const [sortAsc, setSortAsc] = useState<boolean>(false);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  // Status Counts
  const counts = useMemo(() => {
    return {
      all: events.length,
      open: events.filter((e) => e.status === 'Open').length,
      investigating: events.filter((e) => e.status === 'Investigating').length,
      resolved: events.filter((e) => e.status === 'Resolved').length,
      falsePositive: events.filter((e) => e.status === 'False Positive').length,
      critical: events.filter((e) => e.severity === 'Critical').length,
    };
  }, [events]);

  // Filtered & Sorted Events
  const filteredEvents = useMemo(() => {
    return events
      .filter((e) => {
        if (selectedStatus !== 'All' && e.status !== selectedStatus) return false;
        if (selectedSeverity !== 'All' && e.severity !== selectedSeverity) return false;
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase();
          const matchId = e.id.toLowerCase().includes(q);
          const matchCat = e.category.toLowerCase().includes(q);
          const matchIp = e.srcIp.includes(q) || e.dstIp.includes(q);
          const matchMitre = e.mitreId.toLowerCase().includes(q) || e.mitreName.toLowerCase().includes(q);
          if (!matchId && !matchCat && !matchIp && !matchMitre) return false;
        }
        return true;
      })
      .sort((a, b) => {
        let diff = 0;
        if (sortField === 'timestamp') {
          diff = new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
        } else if (sortField === 'confidence') {
          diff = b.confidence - a.confidence;
        } else if (sortField === 'severity') {
          const rank: Record<Severity, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
          diff = rank[b.severity] - rank[a.severity];
        }
        return sortAsc ? -diff : diff;
      });
  }, [events, selectedStatus, selectedSeverity, searchQuery, sortField, sortAsc]);

  // Quick Action Handlers
  const handleQuarantine = (e: React.MouseEvent, event: ThreatEvent) => {
    e.stopPropagation();
    onUpdateStatus(event.id, 'Resolved', `[AUTOMATED DEFENSE] Quarantined source IP ${event.srcIp} on perimeter gateway firewall.`);
    setActionNotice(`Source host ${event.srcIp} has been isolated and added to Zero-Trust quarantine.`);
    setTimeout(() => setActionNotice(null), 4000);
  };

  const handleMarkFalsePositive = (e: React.MouseEvent, event: ThreatEvent) => {
    e.stopPropagation();
    onUpdateStatus(event.id, 'False Positive', `[ANALYST OVERRIDE] Marked as legitimate activity after cross-referencing internal change authorization.`);
    setActionNotice(`Incident ${event.id} marked as False Positive. Tuning detection rules.`);
    setTimeout(() => setActionNotice(null), 4000);
  };

  // Export CSV
  const handleExportCsv = () => {
    const headers = ['ID', 'Timestamp', 'Category', 'Severity', 'Confidence', 'Source_IP', 'Target_IP', 'Protocol', 'Status', 'MITRE_ID'];
    const rows = filteredEvents.map(e => [
      e.id,
      e.timestamp,
      `"${e.category}"`,
      e.severity,
      (e.confidence * 100).toFixed(1) + '%',
      e.srcIp,
      e.dstIp,
      e.protocol,
      e.status,
      e.mitreId
    ]);
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `sentinel_incidents_${new Date().toISOString().split('T')[0]}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  return (
    <div className="space-y-8 pb-16">
      {/* Top Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <div className="flex items-center gap-2">
            <span className="flex h-2 w-2 rounded-full bg-cyan-400 animate-ping" />
            <span className="mono text-xs font-bold text-cyan-400 uppercase tracking-widest">
              SOC INCIDENT MANAGEMENT ENGINE
            </span>
            <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] font-semibold text-slate-400">
              SIMULATED TELEMETRY
            </span>
          </div>
          <h1 className="text-3xl font-black tracking-tight text-white mt-1">
            Security Incident Queue & Alert Center
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Triage, investigate, and remediate high-confidence security incidents. Apply automated edge firewall quarantines, 
            record analyst audit logs, and synchronize alert lifecycle states.
          </p>
        </div>

        {/* Global Export & Batch Actions */}
        <div className="flex items-center gap-3">
          <button
            onClick={handleExportCsv}
            className="flex items-center gap-2 rounded-xl border border-slate-700 bg-obsidian-900/80 px-4 py-2.5 text-xs font-bold text-slate-300 hover:bg-slate-800 hover:border-slate-600 transition-all shadow-md"
          >
            <FileSpreadsheet className="h-4 w-4 text-emerald-400" />
            <span>Export CSV Audit</span>
          </button>
        </div>
      </div>

      {/* Action Notification Banner */}
      <AnimatePresence>
        {actionNotice && (
          <motion.div
            initial={{ opacity: 0, y: -15 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -15 }}
            className="rounded-xl border border-cyan-500/50 bg-cyan-950/40 p-3.5 text-xs font-bold text-cyan-300 flex items-center gap-2 shadow-lg shadow-cyan-500/10 backdrop-blur-md"
          >
            <ShieldCheck className="h-4 w-4 text-cyan-400" />
            <span>{actionNotice}</span>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Lifecycle Stat Metric Tiles */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { label: 'ALL INCIDENTS', count: counts.all, color: 'text-white', borderColor: 'border-slate-800' },
          { label: 'OPEN / UNTRIAGED', count: counts.open, color: 'text-rose-400', borderColor: 'border-rose-500/30' },
          { label: 'IN FORENSIC REVIEW', count: counts.investigating, color: 'text-amber-400', borderColor: 'border-amber-500/30' },
          { label: 'REMEDIATED / CLOSED', count: counts.resolved, color: 'text-emerald-400', borderColor: 'border-emerald-500/30' },
          { label: 'FALSE POSITIVE', count: counts.falsePositive, color: 'text-slate-400', borderColor: 'border-slate-700' },
        ].map((item) => (
          <div
            key={item.label}
            className={`rounded-xl border ${item.borderColor} bg-obsidian-900/60 p-4 backdrop-blur-md`}
          >
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
              {item.label}
            </span>
            <div className={`mono text-2xl font-black mt-1 ${item.color}`}>{item.count}</div>
          </div>
        ))}
      </div>

      {/* Filter and Control Bar */}
      <div className="rounded-2xl border border-slate-800 bg-obsidian-900/70 p-4 backdrop-blur-xl space-y-4">
        {/* Status Tabs */}
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-1.5 p-1 rounded-xl bg-obsidian-950 border border-slate-800">
            {['All', 'Open', 'Investigating', 'Resolved', 'False Positive'].map((status) => (
              <button
                key={status}
                onClick={() => setSelectedStatus(status)}
                className={`rounded-lg px-3.5 py-1.5 text-xs font-bold transition-all ${
                  selectedStatus === status
                    ? 'bg-cyan-500 text-obsidian-950 shadow-md shadow-cyan-500/30'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {status}
              </button>
            ))}
          </div>

          {/* Search Field */}
          <div className="relative min-w-[280px]">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by IP, ID, MITRE, category..."
              className="w-full rounded-xl border border-slate-700 bg-obsidian-950 pl-9 pr-4 py-2 text-xs text-white placeholder-slate-400 focus:border-cyan-400 focus:outline-none"
            />
          </div>
        </div>

        {/* Secondary Filters & Sort Controls */}
        <div className="flex flex-wrap items-center justify-between gap-4 pt-2 border-t border-slate-800/80 text-xs text-slate-400">
          <div className="flex items-center gap-3">
            <span className="font-semibold text-slate-300">Severity Filter:</span>
            <div className="flex items-center gap-1">
              {['All', 'Critical', 'High', 'Medium', 'Low'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSelectedSeverity(sev)}
                  className={`rounded px-2.5 py-1 text-[11px] font-bold transition-all ${
                    selectedSeverity === sev
                      ? 'bg-slate-700 text-white border border-slate-600'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          <div className="flex items-center gap-3">
            <span className="font-semibold text-slate-300">Sort by:</span>
            <div className="flex items-center gap-1">
              {[
                { id: 'timestamp', label: 'Timestamp' },
                { id: 'confidence', label: 'Confidence' },
                { id: 'severity', label: 'Severity' },
              ].map((s) => (
                <button
                  key={s.id}
                  onClick={() => {
                    if (sortField === s.id) {
                      setSortAsc(!sortAsc);
                    } else {
                      setSortField(s.id as any);
                      setSortAsc(false);
                    }
                  }}
                  className={`flex items-center gap-1 rounded px-2.5 py-1 text-[11px] font-bold ${
                    sortField === s.id ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <span>{s.label}</span>
                  {sortField === s.id && (
                    <ArrowUpDown className="h-3 w-3" />
                  )}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Incident List Table */}
      <div className="rounded-2xl border border-slate-800 bg-obsidian-900/60 overflow-hidden backdrop-blur-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 bg-obsidian-950/80 text-[10px] font-bold text-slate-400 uppercase tracking-wider">
              <tr>
                <th className="py-3.5 px-4">Incident ID</th>
                <th className="py-3.5 px-4">Timestamp</th>
                <th className="py-3.5 px-4">Threat Scenario</th>
                <th className="py-3.5 px-4">Severity / Score</th>
                <th className="py-3.5 px-4">Endpoints</th>
                <th className="py-3.5 px-4">Status</th>
                <th className="py-3.5 px-4 text-right">Triage Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400">
                    No security incidents match your filter query.
                  </td>
                </tr>
              ) : (
                filteredEvents.map((event) => {
                  return (
                    <tr
                      key={event.id}
                      onClick={() => onOpenDrawer(event)}
                      className="group cursor-pointer hover:bg-obsidian-800/50 transition-colors"
                    >
                      {/* ID & MITRE */}
                      <td className="py-3.5 px-4">
                        <div className="mono font-bold text-cyan-400 group-hover:text-cyan-300">
                          {event.id}
                        </div>
                        <div className="text-[10px] text-slate-400 mono mt-0.5">{event.mitreId}</div>
                      </td>

                      {/* Timestamp */}
                      <td className="py-3.5 px-4 mono text-slate-300 text-[11px] whitespace-nowrap">
                        {event.timestamp.replace('T', ' ').slice(0, 19)}
                      </td>

                      {/* Threat Category */}
                      <td className="py-3.5 px-4">
                        <div className="font-bold text-white group-hover:text-cyan-200">
                          {event.category}
                        </div>
                        <div className="text-[10px] text-slate-400 max-w-xs truncate mt-0.5">
                          {event.evidence}
                        </div>
                      </td>

                      {/* Severity & Confidence */}
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <span
                          className={`inline-block rounded px-2 py-0.5 text-[10px] font-black uppercase ${
                            event.severity === 'Critical'
                              ? 'bg-red-950/80 text-red-400 border border-red-500/50'
                              : event.severity === 'High'
                              ? 'bg-amber-950/80 text-amber-400 border border-amber-500/50'
                              : event.severity === 'Medium'
                              ? 'bg-yellow-950/80 text-yellow-400 border border-yellow-500/50'
                              : 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/50'
                          }`}
                        >
                          {event.severity}
                        </span>
                        <div className="text-[10px] mono text-slate-400 mt-1">
                          {Math.round(event.confidence * 100)}% Conf
                        </div>
                      </td>

                      {/* Endpoints */}
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <div className="mono text-slate-200">
                          <span className="text-cyan-400">{event.srcIp}</span>:{event.srcPort}
                        </div>
                        <div className="mono text-[10px] text-slate-400 mt-0.5">
                          &rarr; {event.dstIp}:{event.dstPort} ({event.protocol})
                        </div>
                      </td>

                      {/* Status Dropdown */}
                      <td className="py-3.5 px-4 whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                        <select
                          value={event.status}
                          onChange={(e) => onUpdateStatus(event.id, e.target.value as AlertStatus)}
                          className={`rounded-lg border px-2.5 py-1 text-xs font-bold transition-all focus:outline-none ${
                            event.status === 'Open'
                              ? 'bg-red-950/60 border-red-500/40 text-red-300'
                              : event.status === 'Investigating'
                              ? 'bg-amber-950/60 border-amber-500/40 text-amber-300'
                              : event.status === 'Resolved'
                              ? 'bg-emerald-950/60 border-emerald-500/40 text-emerald-300'
                              : 'bg-slate-800 border-slate-700 text-slate-400'
                          }`}
                        >
                          <option value="Open">Open</option>
                          <option value="Investigating">Investigating</option>
                          <option value="Resolved">Resolved</option>
                          <option value="False Positive">False Positive</option>
                        </select>
                      </td>

                      {/* Quick Triage Buttons */}
                      <td className="py-3.5 px-4 text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            title="Quarantine Attacker IP"
                            onClick={(e) => handleQuarantine(e, event)}
                            className="rounded p-1.5 text-slate-400 hover:text-red-400 hover:bg-red-950/40 border border-transparent hover:border-red-500/30 transition-all"
                          >
                            <Ban className="h-4 w-4" />
                          </button>
                          <button
                            title="Mark False Positive"
                            onClick={(e) => handleMarkFalsePositive(e, event)}
                            className="rounded p-1.5 text-slate-400 hover:text-emerald-400 hover:bg-emerald-950/40 border border-transparent hover:border-emerald-500/30 transition-all"
                          >
                            <ShieldCheck className="h-4 w-4" />
                          </button>
                          <button
                            title="Inspect Forensic Dossier"
                            onClick={() => onOpenDrawer(event)}
                            className="rounded p-1.5 text-slate-400 hover:text-cyan-400 hover:bg-cyan-950/40 border border-transparent hover:border-cyan-500/30 transition-all"
                          >
                            <ExternalLink className="h-4 w-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
