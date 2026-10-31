import React, { useState } from 'react';
import { ThreatEvent, ThreatCategory, Severity } from '../types';
import { EventRibbon } from '../components/EventRibbon';
import { Search, Filter, SlidersHorizontal, ArrowUpDown } from 'lucide-react';

interface ThreatExplorerProps {
  events: ThreatEvent[];
  onSelectEvent: (event: ThreatEvent) => void;
  selectedEventId?: string;
}

export const ThreatExplorer: React.FC<ThreatExplorerProps> = ({
  events,
  onSelectEvent,
  selectedEventId,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('All');
  const [categoryFilter, setCategoryFilter] = useState<string>('All');
  const [sortBy, setSortBy] = useState<'timestamp' | 'confidence' | 'severity'>('timestamp');

  const filteredEvents = events.filter((e) => {
    if (severityFilter !== 'All' && e.severity !== severityFilter) return false;
    if (categoryFilter !== 'All' && e.category !== categoryFilter) return false;
    if (searchTerm.trim()) {
      const q = searchTerm.toLowerCase();
      const match =
        e.id.toLowerCase().includes(q) ||
        e.srcIp.toLowerCase().includes(q) ||
        e.dstIp.toLowerCase().includes(q) ||
        e.category.toLowerCase().includes(q) ||
        e.evidence.toLowerCase().includes(q);
      if (!match) return false;
    }
    return true;
  });

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="border-b border-slate-800 pb-5">
        <div className="flex items-center gap-2">
          <h1 className="text-2xl font-black text-white uppercase tracking-tight">
            FORENSIC THREAT EXPLORER & INCIDENT LOGS
          </h1>
          <span className="rounded bg-cyan-950 px-2 py-0.5 text-[10px] font-bold text-cyan-400 border border-cyan-800/50">
            {filteredEvents.length} RECORDS MATCHED
          </span>
        </div>
        <p className="text-xs text-slate-400 mt-1">
          Perform granular forensic investigations by filtering on IP ranges, ports, protocols, and payload indicators.
        </p>
      </div>

      {/* Filter Toolbar */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-3.5 rounded-2xl border border-slate-800 bg-obsidian-900/90 p-4 shadow-xl backdrop-blur-xl">
        <div className="md:col-span-4 relative">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search IP, Event ID, Category, or Evidence..."
            className="w-full rounded-xl border border-slate-700 bg-obsidian-950 pl-9 pr-4 py-2 text-xs font-mono font-bold text-white focus:border-cyan-400 focus:outline-none"
          />
        </div>

        <div className="md:col-span-3">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="w-full rounded-xl border border-slate-700 bg-obsidian-950 px-3 py-2 text-xs font-bold text-white focus:border-cyan-400 focus:outline-none"
          >
            <option value="All">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Info">Info</option>
          </select>
        </div>

        <div className="md:col-span-3">
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="w-full rounded-xl border border-slate-700 bg-obsidian-950 px-3 py-2 text-xs font-bold text-white focus:border-cyan-400 focus:outline-none"
          >
            <option value="All">All Threat Vectors</option>
            <option value="Brute-Force Login">Brute-Force Login</option>
            <option value="Port Scanning">Port Scanning</option>
            <option value="Abnormally High Traffic">Abnormally High Traffic</option>
            <option value="Suspicious User Behaviour">Suspicious User Behaviour</option>
            <option value="Malicious URL/Indicator">Malicious URL/Indicator</option>
            <option value="Benign">Benign Operational</option>
          </select>
        </div>

        <div className="md:col-span-2">
          <button
            onClick={() => {
              setSearchTerm('');
              setSeverityFilter('All');
              setCategoryFilter('All');
            }}
            className="w-full rounded-xl border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-bold text-slate-300 hover:bg-slate-700 hover:text-white"
          >
            Reset Filters
          </button>
        </div>
      </div>

      {/* Events Stream */}
      <div className="space-y-2.5">
        {filteredEvents.length === 0 ? (
          <div className="rounded-2xl border border-slate-800 bg-obsidian-900/60 p-12 text-center">
            <p className="text-sm font-bold text-slate-400">No threat events match the specified filter criteria.</p>
            <p className="text-xs text-slate-600 mt-1">Try resetting the filters or broadening your search terms.</p>
          </div>
        ) : (
          filteredEvents.map((event) => (
            <EventRibbon
              key={event.id}
              event={event}
              onSelect={onSelectEvent}
              isSelected={selectedEventId === event.id}
            />
          ))
        )}
      </div>
    </div>
  );
};
