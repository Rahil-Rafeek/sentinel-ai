import React from 'react';
import { motion } from 'framer-motion';
import { 
  Play, 
  Pause, 
  Square, 
  FastForward, 
  Radio, 
  Activity, 
  RefreshCw,
  Flame,
  CheckCircle2
} from 'lucide-react';
import { ReplayState } from '../services/api';

interface ReplayControlBarProps {
  replayState: ReplayState;
  onStartReplay: () => void;
  onPauseReplay: () => void;
  onResumeReplay: () => void;
  onStopReplay: () => void;
  onSetSpeed: (speed: number) => void;
}

export const ReplayControlBar: React.FC<ReplayControlBarProps> = ({
  replayState,
  onStartReplay,
  onPauseReplay,
  onResumeReplay,
  onStopReplay,
  onSetSpeed,
}) => {
  const isPlaying = replayState.status === 'playing';
  const isPaused = replayState.status === 'paused';
  const progressPct = replayState.total_events > 0 
    ? Math.min(100, (replayState.current_index / replayState.total_events) * 100)
    : 0;

  return (
    <div className="relative overflow-hidden rounded-2xl border border-cyan-500/30 bg-gradient-to-r from-obsidian-950 via-obsidian-900/90 to-obsidian-950 p-4 shadow-xl shadow-cyan-500/10 backdrop-blur-xl">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        {/* Left: Replay Status & Identity */}
        <div className="flex items-center gap-3">
          <div className={`flex h-10 w-10 items-center justify-center rounded-xl border ${
            isPlaying 
              ? 'bg-cyan-950/60 border-cyan-400/50 text-cyan-400' 
              : 'bg-slate-900 border-slate-800 text-slate-400'
          }`}>
            <Radio className={`h-5 w-5 ${isPlaying ? 'animate-pulse text-cyan-400' : ''}`} />
          </div>

          <div>
            <div className="flex items-center gap-2">
              <span className="mono text-xs font-black tracking-wider text-cyan-400 uppercase">
                TIME-SERIES REPLAY ENGINE
              </span>
              <span className="rounded bg-cyan-950/80 border border-cyan-500/40 px-2 py-0.5 text-[10px] font-bold text-cyan-300">
                {replayState.status.toUpperCase()}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Replaying analyzed dataset telemetry sequentially into the 360° Threat Radar and live alert pipeline.
            </p>
          </div>
        </div>

        {/* Center: Playback Buttons */}
        <div className="flex items-center gap-2">
          {!isPlaying && !isPaused && (
            <button
              onClick={onStartReplay}
              className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 px-4 py-2 text-xs font-black text-obsidian-950 shadow-md shadow-cyan-500/30 hover:brightness-110"
            >
              <Play className="h-4 w-4 fill-obsidian-950" />
              <span>Start Replay</span>
            </button>
          )}

          {isPlaying && (
            <button
              onClick={onPauseReplay}
              className="flex items-center gap-2 rounded-xl border border-amber-500/40 bg-amber-950/40 px-4 py-2 text-xs font-bold text-amber-300 hover:bg-amber-900/40"
            >
              <Pause className="h-4 w-4" />
              <span>Pause</span>
            </button>
          )}

          {isPaused && (
            <button
              onClick={onResumeReplay}
              className="flex items-center gap-2 rounded-xl bg-cyan-500 px-4 py-2 text-xs font-black text-obsidian-950 shadow-md shadow-cyan-500/30 hover:brightness-110"
            >
              <Play className="h-4 w-4 fill-obsidian-950" />
              <span>Resume</span>
            </button>
          )}

          {(isPlaying || isPaused) && (
            <button
              onClick={onStopReplay}
              className="flex items-center gap-1.5 rounded-xl border border-slate-700 bg-obsidian-950 px-3 py-2 text-xs font-bold text-slate-400 hover:text-white hover:border-slate-600"
            >
              <Square className="h-3.5 w-3.5 fill-slate-400" />
              <span>Stop</span>
            </button>
          )}

          {/* Speed Selector */}
          <div className="flex items-center gap-1 ml-2 p-1 rounded-lg bg-obsidian-950 border border-slate-800">
            {[0.5, 1.0, 2.0, 5.0].map((s) => (
              <button
                key={s}
                onClick={() => onSetSpeed(s)}
                className={`rounded px-2 py-1 text-[11px] font-bold transition-all ${
                  replayState.speed === s
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {s}x
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Progress Bar & Counter */}
      {(isPlaying || isPaused || replayState.current_index > 0) && (
        <div className="mt-4 pt-3 border-t border-slate-800/80">
          <div className="flex items-center justify-between text-xs mb-1.5">
            <span className="text-slate-400">
              Event <span className="mono font-bold text-white">{replayState.current_index}</span> of{' '}
              <span className="mono font-bold text-white">{replayState.total_events}</span>
            </span>

            <span className="mono text-xs font-bold text-cyan-400">
              {progressPct.toFixed(1)}% Replayed
            </span>
          </div>

          <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
            <motion.div
              initial={false}
              animate={{ width: `${progressPct}%` }}
              transition={{ duration: 0.2 }}
              className="h-full bg-gradient-to-r from-cyan-400 to-violet-500"
            />
          </div>
        </div>
      )}
    </div>
  );
};
