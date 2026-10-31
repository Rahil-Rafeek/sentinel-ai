import React from 'react';
import { INTELLIGENCE_MARQUEE_ITEMS } from '../data/mockData';
import { AlertTriangle, ShieldCheck, Activity, Terminal } from 'lucide-react';

export const IntelligenceMarquee: React.FC = () => {
  return (
    <div className="relative w-full overflow-hidden border-y border-slate-800/80 bg-obsidian-950/90 py-2.5 backdrop-blur-md">
      {/* Subtle Side Vignettes */}
      <div className="pointer-events-none absolute left-0 top-0 bottom-0 z-10 w-24 bg-gradient-to-r from-obsidian-950 to-transparent"></div>
      <div className="pointer-events-none absolute right-0 top-0 bottom-0 z-10 w-24 bg-gradient-to-l from-obsidian-950 to-transparent"></div>

      <div className="flex w-max animate-marquee hover:[animation-play-state:paused] cursor-default">
        {/* Render twice for seamless continuous loop */}
        {[...INTELLIGENCE_MARQUEE_ITEMS, ...INTELLIGENCE_MARQUEE_ITEMS].map((item, index) => {
          let badgeColor = 'bg-cyan-950/40 text-cyan-400 border-cyan-800/50';
          let Icon = Activity;

          if (item.type === 'crit') {
            badgeColor = 'bg-red-950/40 text-red-400 border-red-800/50';
            Icon = AlertTriangle;
          } else if (item.type === 'warn') {
            badgeColor = 'bg-amber-950/40 text-amber-400 border-amber-800/50';
            Icon = Terminal;
          } else if (item.type === 'info') {
            badgeColor = 'bg-violet-950/40 text-violet-400 border-violet-800/50';
            Icon = ShieldCheck;
          }

          return (
            <div
              key={index}
              className="mx-4 flex items-center gap-2.5 whitespace-nowrap rounded-md border border-slate-800/80 bg-obsidian-900/60 px-3 py-1 text-xs font-semibold tracking-wide transition-all hover:border-cyan-500/40 hover:bg-slate-900/80"
            >
              <span className={`flex h-4 w-4 items-center justify-center rounded border text-[10px] ${badgeColor}`}>
                <Icon className="h-2.5 w-2.5" />
              </span>
              <span className="mono text-[11px] font-bold text-slate-200">{item.text}</span>
              <span className="mono text-[10px] text-slate-500">// SIMULATED</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};
