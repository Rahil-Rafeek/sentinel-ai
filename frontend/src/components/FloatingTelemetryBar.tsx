import React from 'react';
import { SystemTelemetry } from '../types';
import { Activity, Radio, Cpu, ShieldAlert, Database } from 'lucide-react';
import { motion } from 'framer-motion';

interface FloatingTelemetryBarProps {
  telemetry: SystemTelemetry;
}

export const FloatingTelemetryBar: React.FC<FloatingTelemetryBarProps> = ({ telemetry }) => {
  const telemetryItems = [
    {
      label: 'INGESTION RATE',
      value: `${telemetry.eventRate.toLocaleString()} PKTS/S`,
      icon: Activity,
      status: 'nominal',
      color: 'text-cyan-400',
      border: 'border-cyan-500/30',
    },
    {
      label: 'CONCURRENT FLOWS',
      value: `${telemetry.activeFlows.toLocaleString()} SESSIONS`,
      icon: Radio,
      status: 'nominal',
      color: 'text-blue-400',
      border: 'border-blue-500/30',
    },
    {
      label: 'THREAT INDEX',
      value: `${telemetry.threatScore}/100 [HIGH]`,
      icon: ShieldAlert,
      status: 'warning',
      color: 'text-red-400',
      border: 'border-red-500/30',
    },
    {
      label: 'INFERENCE ENGINE',
      value: 'RF + RULES HYBRID',
      icon: Cpu,
      status: 'active',
      color: 'text-violet-400',
      border: 'border-violet-500/30',
    },
    {
      label: 'TELEMETRY REPOSITORY',
      value: 'SQLITE PERSISTENT',
      icon: Database,
      status: 'nominal',
      color: 'text-emerald-400',
      border: 'border-emerald-500/30',
    },
  ];

  return (
    <div className="flex w-full flex-wrap items-center justify-between gap-3 p-1">
      {telemetryItems.map((item, idx) => {
        const Icon = item.icon;
        return (
          <motion.div
            key={idx}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: idx * 0.08, duration: 0.3 }}
            whileHover={{ y: -2, scale: 1.01 }}
            className={`flex flex-1 min-w-[200px] items-center gap-3 rounded-xl border ${item.border} bg-obsidian-900/80 px-4 py-2.5 shadow-lg shadow-black/40 backdrop-blur-md transition-all hover:bg-slate-900/90`}
          >
            <div className={`flex h-8 w-8 items-center justify-center rounded-lg bg-obsidian-950 border border-slate-800 ${item.color}`}>
              <Icon className="h-4 w-4" />
            </div>
            <div className="flex-1 truncate">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold tracking-wider text-slate-400 uppercase">
                  {item.label}
                </span>
                <span className="mono text-[8px] text-slate-500">// SIMULATED</span>
              </div>
              <div className={`mono text-xs font-black tracking-tight ${item.color} truncate`}>
                {item.value}
              </div>
            </div>
          </motion.div>
        );
      })}
    </div>
  );
};
