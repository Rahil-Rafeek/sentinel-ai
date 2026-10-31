import React, { useState, useEffect, useRef } from 'react';
import { ThreatEvent } from '../types';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, AlertTriangle, ArrowRight, X } from 'lucide-react';

interface HeroRadarProps {
  events: ThreatEvent[];
  onSelectEvent: (event: ThreatEvent) => void;
  selectedEventId?: string;
}

export const HeroRadar: React.FC<HeroRadarProps> = ({ events, onSelectEvent, selectedEventId }) => {
  const [activeSignal, setActiveSignal] = useState<ThreatEvent | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  // Default active signal
  useEffect(() => {
    if (selectedEventId) {
      const match = events.find((e) => e.id === selectedEventId);
      if (match) setActiveSignal(match);
    } else if (events.length > 0 && !activeSignal) {
      setActiveSignal(events[0]);
    }
  }, [selectedEventId, events]);

  // Sweep line animation on HTML5 Canvas for silky-smooth 60fps rotation
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let angle = 0;
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const radius = Math.min(centerX, centerY) - 20;

    const render = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      // Rotating Sweep Beam
      angle += 0.015;
      if (angle >= Math.PI * 2) angle = 0;

      // Draw phosphor sweep trail
      const gradient = ctx.createConicGradient(angle - Math.PI / 2, centerX, centerY);
      gradient.addColorStop(0, 'rgba(0, 242, 254, 0.25)');
      gradient.addColorStop(0.12, 'rgba(0, 242, 254, 0.05)');
      gradient.addColorStop(0.25, 'rgba(0, 242, 254, 0.0)');
      gradient.addColorStop(1, 'rgba(0, 242, 254, 0.0)');

      ctx.beginPath();
      ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
      ctx.fillStyle = gradient;
      ctx.fill();

      // Leading beam line
      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.lineTo(centerX + Math.cos(angle) * radius, centerY + Math.sin(angle) * radius);
      ctx.strokeStyle = 'rgba(0, 242, 254, 0.8)';
      ctx.lineWidth = 1.5;
      ctx.shadowColor = '#00F2FE';
      ctx.shadowBlur = 8;
      ctx.stroke();
      ctx.shadowBlur = 0;

      animationFrameId = requestAnimationFrame(render);
    };

    render();
    return () => cancelAnimationFrame(animationFrameId);
  }, []);

  const size = 520;
  const center = size / 2;
  const maxR = center - 40;

  // 5 Sector Divisions
  const sectors = [
    { label: 'AUTH BOUNDARY', angle: 36, desc: 'SSH / RDP / Credential Attacks' },
    { label: 'PERIMETER RECON', angle: 108, desc: 'Port Scanning & Sweeps' },
    { label: 'INGRESS FLOOD', angle: 180, desc: 'DDoS / Volumetric Spikes' },
    { label: 'LATERAL / EXFIL', angle: 252, desc: 'Data Egress & Sensitive Endpoints' },
    { label: 'PAYLOAD INDICATOR', angle: 324, desc: 'Malicious URLs & C2 Relays' },
  ];

  return (
    <div className="relative flex flex-col items-center justify-center p-4">
      {/* Ambient Radial Backlight */}
      <div className="pointer-events-none absolute h-[600px] w-[600px] rounded-full bg-gradient-to-tr from-cyan-500/10 via-violet-600/10 to-transparent blur-3xl"></div>

      {/* Floating Status Badge */}
      <div className="absolute top-2 left-4 z-20 flex items-center gap-2 rounded-full border border-cyan-500/30 bg-obsidian-900/90 px-3 py-1 backdrop-blur-md">
        <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse"></span>
        <span className="mono text-[11px] font-bold text-cyan-300">RADAR ACTIVE &bull; 360° TELEMETRY</span>
        <span className="rounded bg-slate-800 px-1.5 text-[9px] font-semibold text-slate-400">DEMO</span>
      </div>

      {/* Main Circular Radar Viewport */}
      <div className="relative h-[520px] w-[520px] max-w-full">
        {/* Canvas for Sweep Beam */}
        <canvas
          ref={canvasRef}
          width={size}
          height={size}
          className="pointer-events-none absolute inset-0 z-0 h-full w-full"
        />

        {/* SVG Concentric Range Rings & Grid lines */}
        <svg className="absolute inset-0 z-10 h-full w-full" viewBox={`0 0 ${size} ${size}`}>
          <defs>
            <radialGradient id="radarCenterGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#00F2FE" stopOpacity="0.12" />
              <stop offset="100%" stopColor="#030509" stopOpacity="0" />
            </radialGradient>
          </defs>

          {/* Central Radial Glow Circle */}
          <circle cx={center} cy={center} r={maxR} fill="url(#radarCenterGlow)" />

          {/* Concentric Severity Rings */}
          <circle cx={center} cy={center} r={maxR} fill="none" stroke="rgba(0, 242, 254, 0.3)" strokeWidth="1.5" />
          <circle cx={center} cy={center} r={maxR * 0.75} fill="none" stroke="rgba(30, 41, 59, 0.8)" strokeWidth="1" strokeDasharray="3 3" />
          <circle cx={center} cy={center} r={maxR * 0.50} fill="none" stroke="rgba(30, 41, 59, 0.8)" strokeWidth="1" strokeDasharray="3 3" />
          <circle cx={center} cy={center} r={maxR * 0.25} fill="none" stroke="rgba(0, 242, 254, 0.2)" strokeWidth="1" />
          <circle cx={center} cy={center} r={4} fill="#00F2FE" />

          {/* Sector Crosshair Lines */}
          {sectors.map((s, idx) => {
            const rad = (s.angle * Math.PI) / 180;
            const x2 = center + Math.cos(rad) * maxR;
            const y2 = center + Math.sin(rad) * maxR;
            return (
              <line
                key={idx}
                x1={center}
                y1={center}
                x2={x2}
                y2={y2}
                stroke="rgba(0, 242, 254, 0.2)"
                strokeWidth="1"
                strokeDasharray="4 4"
              />
            );
          })}

          {/* Connected Vector Lines to Active Signal */}
          {activeSignal && (
            <line
              x1={center}
              y1={center}
              x2={center + Math.cos((activeSignal.radarAngle * Math.PI) / 180) * (activeSignal.radarRadius * maxR)}
              y2={center + Math.sin((activeSignal.radarAngle * Math.PI) / 180) * (activeSignal.radarRadius * maxR)}
              stroke="#00F2FE"
              strokeWidth="2"
              strokeDasharray="2 2"
              className="animate-pulse"
            />
          )}
        </svg>

        {/* Tactical Sector Labels (Orbital) */}
        {sectors.map((s, idx) => {
          const rad = (s.angle * Math.PI) / 180;
          const r = maxR + 18;
          const x = center + Math.cos(rad) * r;
          const y = center + Math.sin(rad) * r;
          return (
            <div
              key={idx}
              className="absolute z-20 -translate-x-1/2 -translate-y-1/2 text-center pointer-events-none"
              style={{ left: `${x}px`, top: `${y}px` }}
            >
              <span className="mono text-[9px] font-bold tracking-wider text-cyan-400 bg-obsidian-950/90 px-1.5 py-0.5 rounded border border-cyan-500/20">
                {s.label}
              </span>
            </div>
          );
        })}

        {/* Interactive Threat Blips (Points) */}
        {events.map((event) => {
          const rad = (event.radarAngle * Math.PI) / 180;
          const dist = event.radarRadius * maxR;
          const x = center + Math.cos(rad) * dist;
          const y = center + Math.sin(rad) * dist;

          const isSelected = activeSignal?.id === event.id;
          let pointColor = 'bg-cyan-400';
          let ringColor = 'border-cyan-400/50';

          if (event.severity === 'Critical') {
            pointColor = 'bg-red-500';
            ringColor = 'border-red-500/60 shadow-lg shadow-red-500/50';
          } else if (event.severity === 'High') {
            pointColor = 'bg-orange-500';
            ringColor = 'border-orange-500/60 shadow-lg shadow-orange-500/50';
          } else if (event.severity === 'Medium') {
            pointColor = 'bg-amber-400';
            ringColor = 'border-amber-400/50';
          } else if (event.severity === 'Low') {
            pointColor = 'bg-emerald-400';
            ringColor = 'border-emerald-400/50';
          }

          return (
            <button
              key={event.id}
              onClick={() => {
                setActiveSignal(event);
                onSelectEvent(event);
              }}
              className="group absolute z-30 -translate-x-1/2 -translate-y-1/2 cursor-pointer focus:outline-none"
              style={{ left: `${x}px`, top: `${y}px` }}
              title={`${event.id} (${event.category})`}
            >
              <div className="relative flex items-center justify-center">
                {/* Outer Ring Pulse */}
                <div
                  className={`h-7 w-7 rounded-full border transition-all duration-300 ${ringColor} ${
                    isSelected ? 'scale-125 bg-white/10 ring-2 ring-cyan-400' : 'group-hover:scale-110'
                  }`}
                />
                {/* Core Blip */}
                <div
                  className={`absolute h-2.5 w-2.5 rounded-full ${pointColor} ${
                    isSelected ? 'animate-ping' : ''
                  }`}
                />
                <div className={`absolute h-2 w-2 rounded-full ${pointColor}`} />
              </div>
            </button>
          );
        })}
      </div>

      {/* Floating Active Signal Intelligence Inspector Panel */}
      <AnimatePresence>
        {activeSignal && (
          <motion.div
            initial={{ opacity: 0, y: 15, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 10, scale: 0.95 }}
            transition={{ duration: 0.25 }}
            className="mt-4 w-full max-w-xl rounded-xl border border-cyan-500/30 bg-obsidian-900/95 p-4 shadow-2xl shadow-cyan-500/10 backdrop-blur-xl"
          >
            <div className="flex items-start justify-between border-b border-slate-800 pb-2.5">
              <div className="flex items-center gap-2.5">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-red-950/50 border border-red-500/40 text-red-400">
                  <AlertTriangle className="h-4 w-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="mono text-xs font-bold text-cyan-400">{activeSignal.id}</span>
                    <span className="rounded bg-red-950/60 border border-red-500/40 px-1.5 py-0.5 text-[10px] font-bold text-red-400 uppercase">
                      {activeSignal.severity}
                    </span>
                  </div>
                  <h4 className="text-sm font-bold text-white">{activeSignal.category}</h4>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <div className="text-right">
                  <div className="text-[10px] text-slate-400 uppercase font-semibold">Confidence</div>
                  <div className="mono text-sm font-black text-cyan-400">
                    {(activeSignal.confidence * 100).toFixed(1)}%
                  </div>
                </div>
                <button
                  onClick={() => setActiveSignal(null)}
                  className="rounded p-1 text-slate-400 hover:text-white hover:bg-slate-800"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            </div>

            <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
              <div className="rounded bg-obsidian-950/80 p-2 border border-slate-800">
                <span className="text-[10px] text-slate-400 uppercase font-bold">Flow Trajectory</span>
                <div className="mono text-[11px] font-bold text-slate-200 mt-0.5 truncate">
                  {activeSignal.srcIp}:{activeSignal.srcPort} &rarr; {activeSignal.dstIp}:{activeSignal.dstPort}
                </div>
              </div>
              <div className="rounded bg-obsidian-950/80 p-2 border border-slate-800">
                <span className="text-[10px] text-slate-400 uppercase font-bold">Detection Vector</span>
                <div className="mono text-[11px] font-bold text-cyan-300 mt-0.5 truncate">
                  {activeSignal.detectionMethod}
                </div>
              </div>
            </div>

            <p className="mt-2.5 text-xs text-slate-300 line-clamp-2 leading-relaxed">
              <b className="text-cyan-400">Evidence: </b>
              {activeSignal.evidence}
            </p>

            <div className="mt-3 flex items-center justify-between pt-2 border-t border-slate-800/80">
              <span className="mono text-[10px] text-slate-500">
                MITRE ATT&CK: <span className="text-slate-300 font-bold">{activeSignal.mitreId}</span>
              </span>
              <button
                onClick={() => onSelectEvent(activeSignal)}
                className="flex items-center gap-1.5 rounded-lg bg-cyan-500/20 border border-cyan-400/40 px-3 py-1 text-xs font-bold text-cyan-300 transition-all hover:bg-cyan-500/30"
              >
                <span>Full Telemetry Dossier</span>
                <ArrowRight className="h-3 w-3" />
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};
