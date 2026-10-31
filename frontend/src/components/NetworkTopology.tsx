import React, { useState } from 'react';
import { MOCK_NETWORK_NODES, MOCK_NETWORK_LINKS } from '../data/mockData';
import { NetworkNode } from '../types';
import { ShieldAlert, Server, Globe, Lock, Activity } from 'lucide-react';
import { motion } from 'framer-motion';

export const NetworkTopology: React.FC = () => {
  const [selectedNode, setSelectedNode] = useState<NetworkNode | null>(MOCK_NETWORK_NODES[0]);

  return (
    <div className="relative w-full rounded-2xl border border-slate-800 bg-obsidian-900/80 p-6 shadow-2xl backdrop-blur-xl">
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-base font-black text-white uppercase tracking-wider">
              SPATIAL ATTACK GRAPH & PROPAGATION PATHWAYS
            </h3>
            <span className="rounded bg-cyan-950 px-2 py-0.5 text-[10px] font-bold text-cyan-400 border border-cyan-800/40">
              LIVE TOPOLOGY
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time adversary vector tracing: External Attackers &rarr; Perimeter Gateways &rarr; Protected Internal Clusters.
          </p>
        </div>

        <div className="flex items-center gap-4 text-xs font-semibold">
          <div className="flex items-center gap-1.5 text-red-400">
            <span className="h-2 w-2 rounded-full bg-red-400"></span>
            <span>Compromised</span>
          </div>
          <div className="flex items-center gap-1.5 text-amber-400">
            <span className="h-2 w-2 rounded-full bg-amber-400"></span>
            <span>Target Boundary</span>
          </div>
          <div className="flex items-center gap-1.5 text-cyan-400">
            <span className="h-2 w-2 rounded-full bg-cyan-400"></span>
            <span>Secured Node</span>
          </div>
        </div>
      </div>

      <div className="relative mt-6 h-[460px] w-full overflow-hidden rounded-xl border border-slate-800/80 bg-obsidian-950/90">
        {/* SVG Network Lines with Animated Packets */}
        <svg className="absolute inset-0 h-full w-full pointer-events-none" viewBox="0 0 800 700">
          <defs>
            <linearGradient id="linkGradCrit" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#EF4444" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#8B5CF6" stopOpacity="0.4" />
            </linearGradient>
            <linearGradient id="linkGradHigh" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#F97316" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#00F2FE" stopOpacity="0.4" />
            </linearGradient>
          </defs>

          {MOCK_NETWORK_LINKS.map((link, idx) => {
            const sNode = MOCK_NETWORK_NODES.find((n) => n.id === link.source);
            const tNode = MOCK_NETWORK_NODES.find((n) => n.id === link.target);
            if (!sNode || !tNode) return null;

            const isHighlighted = selectedNode?.id === sNode.id || selectedNode?.id === tNode.id;

            return (
              <g key={idx}>
                {/* Flow Line */}
                <line
                  x1={sNode.x}
                  y1={sNode.y}
                  x2={tNode.x}
                  y2={tNode.y}
                  stroke={link.severity === 'Critical' ? 'url(#linkGradCrit)' : 'url(#linkGradHigh)'}
                  strokeWidth={isHighlighted ? 3 : 1.5}
                  strokeDasharray={isHighlighted ? '6 4' : 'none'}
                  strokeOpacity={isHighlighted ? 1 : 0.4}
                />
                {/* Moving Packet Pulse */}
                <circle r={isHighlighted ? 4 : 2.5} fill={link.severity === 'Critical' ? '#EF4444' : '#00F2FE'}>
                  <animateMotion
                    path={`M ${sNode.x} ${sNode.y} L ${tNode.x} ${tNode.y}`}
                    dur={`${2.5 + (idx % 3) * 0.8}s`}
                    repeatCount="indefinite"
                  />
                </circle>
              </g>
            );
          })}
        </svg>

        {/* Interactive Nodes */}
        {MOCK_NETWORK_NODES.map((node) => {
          const isSelected = selectedNode?.id === node.id;
          let nodeColor = 'border-cyan-400 bg-cyan-950/80 text-cyan-300';
          let Icon = Server;

          if (node.type === 'attacker') {
            nodeColor = 'border-red-500 bg-red-950/80 text-red-400';
            Icon = ShieldAlert;
          } else if (node.type === 'gateway') {
            nodeColor = 'border-violet-500 bg-violet-950/80 text-violet-300';
            Icon = Globe;
          } else if (node.type === 'target') {
            nodeColor = 'border-amber-400 bg-amber-950/80 text-amber-300';
            Icon = Lock;
          }

          return (
            <motion.div
              key={node.id}
              onClick={() => setSelectedNode(node)}
              whileHover={{ scale: 1.08 }}
              className={`group absolute -translate-x-1/2 -translate-y-1/2 cursor-pointer z-20 ${
                isSelected ? 'ring-2 ring-cyan-400 rounded-xl' : ''
              }`}
              style={{ left: `${(node.x / 800) * 100}%`, top: `${(node.y / 700) * 100}%` }}
            >
              <div
                className={`flex items-center gap-2 rounded-xl border px-3 py-1.5 shadow-xl backdrop-blur-md transition-all ${nodeColor} ${
                  isSelected ? 'shadow-cyan-500/30' : ''
                }`}
              >
                <Icon className="h-4 w-4" />
                <div>
                  <div className="text-[11px] font-bold tracking-tight text-white">{node.label}</div>
                  <div className="mono text-[9px] text-slate-400">
                    {node.threatCount} threats &bull; {node.ip}
                  </div>
                </div>
              </div>
            </motion.div>
          );
        })}

        {/* Floating Node Inspector (Bottom Right) */}
        {selectedNode && (
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            className="absolute bottom-4 right-4 z-30 w-72 rounded-xl border border-cyan-500/40 bg-obsidian-900/95 p-3.5 shadow-2xl backdrop-blur-xl"
          >
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <span className="mono text-[10px] font-bold text-cyan-400 uppercase">INSPECTED ASSET</span>
              <span className="mono rounded bg-slate-800 px-1.5 py-0.5 text-[9px] font-semibold text-slate-300">
                {selectedNode.type.toUpperCase()}
              </span>
            </div>
            <div className="mt-2 text-xs font-bold text-white">{selectedNode.label}</div>
            <div className="mono text-[11px] text-slate-400 mt-0.5">IP: {selectedNode.ip}</div>
            <div className="mt-2 flex items-center justify-between rounded bg-obsidian-950 p-2 border border-slate-800">
              <span className="text-[10px] text-slate-400 uppercase font-semibold">Correlated Incidents</span>
              <span className="mono text-xs font-black text-red-400">{selectedNode.threatCount} Attacks</span>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
};
