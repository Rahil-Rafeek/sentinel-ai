import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Radio, 
  Activity, 
  Eye, 
  Sliders, 
  Bell, 
  Cpu, 
  Compass, 
  Database, 
  UploadCloud, 
  ChevronDown 
} from 'lucide-react';
import { motion } from 'framer-motion';
import { DatasetItem } from '../services/api';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  datasets?: DatasetItem[];
  activeDatasetId?: string | null;
  onSelectDataset?: (id: string) => void;
  onOpenUploadModal?: () => void;
  criticalCount?: number;
  postureLevel?: string;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  datasets = [],
  activeDatasetId,
  onSelectDataset,
  onOpenUploadModal,
  criticalCount = 18,
  postureLevel = 'DEFCON 2',
}) => {
  const [timeStr, setTimeStr] = useState<string>('');
  const [datasetDropdownOpen, setDatasetDropdownOpen] = useState(false);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTimeStr(now.toTimeString().split(' ')[0] + ' UTC');
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const navItems = [
    { id: 'command', label: 'Command Center', icon: Compass },
    { id: 'intelligence', label: 'Threat Intelligence', icon: Radio },
    { id: 'explorer', label: 'Threat Explorer', icon: Eye },
    { id: 'analytics', label: 'Security Analytics', icon: Activity },
    { id: 'playground', label: 'Detection Playground', icon: Sliders },
    { id: 'alerts', label: 'Alert Center', icon: Bell },
    { id: 'monitor', label: 'System Monitor', icon: Cpu },
  ];

  const activeDataset = datasets.find(d => d.id === activeDatasetId) || datasets[0];

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800/80 bg-obsidian-950/80 backdrop-blur-xl">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        {/* Brand Logo & Core Posture Indicator */}
        <div className="flex items-center gap-4">
          <div className="relative flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500/20 to-violet-600/30 border border-cyan-400/40 shadow-lg shadow-cyan-500/20">
            <Shield className="h-5 w-5 text-cyan-400" />
            <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
            </span>
          </div>

          <div>
            <div className="flex items-center gap-2">
              <span className="text-lg font-black tracking-tight text-white">SENTINEL</span>
              <span className="text-lg font-black text-cyan-400">// AI</span>
              <span className="rounded bg-cyan-950/80 px-1.5 py-0.5 text-[10px] font-bold tracking-wider text-cyan-400 border border-cyan-500/30 uppercase">
                ACTIVE
              </span>
            </div>
            <p className="text-[10px] font-semibold tracking-wider text-slate-400 uppercase">
              POSTURE: {postureLevel}
            </p>
          </div>
        </div>

        {/* Global Dataset Selector & Upload CTA */}
        <div className="hidden md:flex items-center gap-2">
          <div className="relative">
            <button
              onClick={() => setDatasetDropdownOpen(!datasetDropdownOpen)}
              className="flex items-center gap-2 rounded-xl border border-slate-800 bg-obsidian-900/90 px-3 py-1.5 text-xs font-semibold text-slate-300 hover:border-slate-700 hover:text-white transition-all shadow-sm"
            >
              <Database className="h-3.5 w-3.5 text-cyan-400" />
              <span className="max-w-[140px] truncate font-mono text-[11px]">
                {activeDataset ? activeDataset.filename : 'No Dataset Selected'}
              </span>
              <ChevronDown className="h-3 w-3 text-slate-400" />
            </button>

            {/* Dropdown Menu */}
            {datasetDropdownOpen && (
              <div className="absolute left-0 mt-2 w-64 rounded-xl border border-slate-800 bg-obsidian-950/98 p-2 shadow-2xl shadow-cyan-500/10 z-50">
                <div className="px-2 py-1 text-[10px] font-bold uppercase text-slate-400 tracking-wider">
                  Select Analyzed Dataset
                </div>
                <div className="max-h-48 overflow-y-auto space-y-1 my-1">
                  {datasets.map((d) => (
                    <button
                      key={d.id}
                      onClick={() => {
                        if (onSelectDataset) onSelectDataset(d.id);
                        setDatasetDropdownOpen(false);
                      }}
                      className={`w-full flex items-center justify-between rounded-lg px-2.5 py-1.5 text-xs text-left transition-colors ${
                        d.id === activeDatasetId
                          ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-500/30'
                          : 'text-slate-300 hover:bg-slate-900'
                      }`}
                    >
                      <span className="truncate font-mono text-[11px]">{d.filename}</span>
                      <span className="text-[10px] text-slate-400">
                        {d.row_count.toLocaleString()} rows
                      </span>
                    </button>
                  ))}
                  {datasets.length === 0 && (
                    <div className="p-2 text-xs text-slate-400 text-center">No datasets uploaded yet</div>
                  )}
                </div>

                <div className="pt-2 border-t border-slate-800">
                  <button
                    onClick={() => {
                      setDatasetDropdownOpen(false);
                      if (onOpenUploadModal) onOpenUploadModal();
                    }}
                    className="w-full flex items-center justify-center gap-1.5 rounded-lg bg-cyan-500/20 border border-cyan-500/40 py-1.5 text-xs font-bold text-cyan-300 hover:bg-cyan-500/30 transition-all"
                  >
                    <UploadCloud className="h-3.5 w-3.5" />
                    <span>Upload New Dataset</span>
                  </button>
                </div>
              </div>
            )}
          </div>

          <button
            onClick={onOpenUploadModal}
            className="flex items-center gap-1.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 px-3 py-1.5 text-xs font-black text-obsidian-950 shadow-md shadow-cyan-500/25 hover:brightness-110 transition-all"
          >
            <UploadCloud className="h-3.5 w-3.5" />
            <span className="hidden lg:inline">Upload CSV</span>
          </button>
        </div>

        {/* Navigation Tabs with Animated Underline */}
        <nav className="hidden lg:flex items-center gap-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`relative flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-semibold tracking-wide transition-all ${
                  isActive
                    ? 'text-cyan-400 bg-cyan-950/40'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
                }`}
              >
                <Icon className={`h-3.5 w-3.5 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span>{item.label}</span>
                {isActive && (
                  <motion.div
                    layoutId="activeTabBadge"
                    className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-cyan-400 to-violet-500 shadow-sm shadow-cyan-400"
                    transition={{ type: 'spring', stiffness: 450, damping: 35 }}
                  />
                )}
              </button>
            );
          })}
        </nav>

        {/* Live Status HUD & Synthetic Clock */}
        <div className="flex items-center gap-3">
          <div className="hidden sm:flex items-center gap-2 rounded-lg border border-slate-800 bg-obsidian-900/90 px-3 py-1.5">
            <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span className="mono text-[11px] font-bold text-slate-300">{timeStr || '12:00:00 UTC'}</span>
          </div>

          <div className="rounded-lg border border-red-500/40 bg-red-950/20 px-3 py-1.5 text-xs font-bold text-red-400 flex items-center gap-2">
            <span className="h-1.5 w-1.5 rounded-full bg-red-400"></span>
            <span>{criticalCount} CRITICAL</span>
          </div>
        </div>
      </div>
    </header>
  );
};
