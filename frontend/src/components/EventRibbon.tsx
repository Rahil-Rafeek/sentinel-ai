import React from 'react';
import { ThreatEvent } from '../types';
import { motion } from 'framer-motion';
import { ArrowRight, ShieldAlert, AlertTriangle, Info, CheckCircle } from 'lucide-react';

interface EventRibbonProps {
  event: ThreatEvent;
  onSelect: (event: ThreatEvent) => void;
  isSelected?: boolean;
}

export const EventRibbon: React.FC<EventRibbonProps> = ({ event, onSelect, isSelected }) => {
  let sevBadge = 'bg-red-950/70 text-red-400 border-red-500/50';
  let Icon = ShieldAlert;

  if (event.severity === 'High') {
    sevBadge = 'bg-orange-950/70 text-orange-400 border-orange-500/50';
    Icon = AlertTriangle;
  } else if (event.severity === 'Medium') {
    sevBadge = 'bg-amber-950/70 text-amber-400 border-amber-500/50';
    Icon = AlertTriangle;
  } else if (event.severity === 'Low') {
    sevBadge = 'bg-emerald-950/70 text-emerald-400 border-emerald-500/50';
    Icon = CheckCircle;
  } else if (event.severity === 'Info') {
    sevBadge = 'bg-cyan-950/70 text-cyan-400 border-cyan-500/50';
    Icon = Info;
  }

  return (
    <motion.div
      whileHover={{ scale: 1.008, x: 2 }}
      onClick={() => onSelect(event)}
      className={`group relative flex cursor-pointer items-center justify-between gap-4 rounded-xl border p-3 transition-all ${
        isSelected
          ? 'border-cyan-400 bg-cyan-950/30 shadow-lg shadow-cyan-500/20'
          : 'border-slate-800/80 bg-obsidian-900/70 hover:border-slate-700 hover:bg-slate-900/80'
      }`}
    >
      {/* Left indicator accent */}
      <div
        className={`absolute left-0 top-2 bottom-2 w-1 rounded-r ${
          event.severity === 'Critical'
            ? 'bg-red-500'
            : event.severity === 'High'
            ? 'bg-orange-500'
            : event.severity === 'Medium'
            ? 'bg-amber-400'
            : 'bg-cyan-400'
        }`}
      />

      <div className="flex items-center gap-3.5 pl-2 truncate">
        <div className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border ${sevBadge}`}>
          <Icon className="h-4 w-4" />
        </div>

        <div className="truncate">
          <div className="flex items-center gap-2">
            <span className="mono text-[11px] font-bold text-cyan-400">{event.id}</span>
            <span className={`rounded border px-1.5 py-0.2 text-[9px] font-black uppercase ${sevBadge}`}>
              {event.severity}
            </span>
            <span className="mono text-[10px] text-slate-400">{event.timestamp}</span>
          </div>
          <div className="text-xs font-bold text-white truncate mt-0.5">{event.category}</div>
        </div>
      </div>

      {/* Network flow badges */}
      <div className="hidden md:flex items-center gap-3">
        <div className="rounded bg-obsidian-950 border border-slate-800 px-2.5 py-1">
          <span className="text-[9px] text-slate-400 uppercase font-bold block">SOURCE</span>
          <span className="mono text-[11px] text-slate-200 font-bold">{event.srcIp}:{event.srcPort}</span>
        </div>
        <div className="rounded bg-obsidian-950 border border-slate-800 px-2.5 py-1">
          <span className="text-[9px] text-slate-400 uppercase font-bold block">TARGET</span>
          <span className="mono text-[11px] text-violet-300 font-bold">{event.dstIp}:{event.dstPort}</span>
        </div>
      </div>

      {/* Detection Method & Action trigger */}
      <div className="flex items-center gap-3 shrink-0">
        <div className="hidden lg:block text-right">
          <div className="mono text-[10px] text-slate-400 truncate max-w-[150px]">{event.detectionMethod}</div>
          <div className="mono text-[11px] font-black text-cyan-400">{(event.confidence * 100).toFixed(0)}% Conf.</div>
        </div>

        <div className="flex h-7 w-7 items-center justify-center rounded-lg border border-slate-800 bg-obsidian-950 text-slate-400 group-hover:border-cyan-400 group-hover:text-cyan-400">
          <ArrowRight className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5" />
        </div>
      </div>
    </motion.div>
  );
};
