import React, { useState } from 'react';
import { NetworkTopology } from '../components/NetworkTopology';
import { Search, ShieldAlert, CheckCircle, AlertTriangle, ExternalLink, Globe } from 'lucide-react';

export const ThreatIntelligence: React.FC = () => {
  const [iocQuery, setIocQuery] = useState('185.220.101.5');
  const [iocResult, setIocResult] = useState<{
    query: string;
    verdict: 'malicious' | 'suspicious' | 'clean';
    score: number;
    actor: string;
    details: string;
  } | null>({
    query: '185.220.101.5',
    verdict: 'malicious',
    score: 98,
    actor: 'APT-29 / Tor Bulletproof Relay',
    details: 'Verified exit node associated with credential stuffing and command-and-control beacon relay activity.',
  });

  const handleQuery = () => {
    const q = iocQuery.trim();
    if (q === '185.220.101.5' || q === '198.51.100.45' || q.includes('paypal-security')) {
      setIocResult({
        query: q,
        verdict: 'malicious',
        score: 98,
        actor: 'APT-29 / Bulletproof Infrastructure',
        details: 'Confirmed high-risk malicious indicator. Block ingress and egress perimeter traffic immediately.',
      });
    } else if (q.includes('.xyz') || q.includes('.ru') || q.includes('admin')) {
      setIocResult({
        query: q,
        verdict: 'suspicious',
        score: 74,
        actor: 'Untrusted TLD / Heuristic Flag',
        details: 'High Shannon entropy or suspicious top-level domain. Requires active EDR host inspection.',
      });
    } else {
      setIocResult({
        query: q,
        verdict: 'clean',
        score: 12,
        actor: 'N/A — Clean Host',
        details: 'Indicator is clean in baseline threat feeds. No active reputation alerts recorded.',
      });
    }
  };

  return (
    <div className="space-y-8 pb-12">
      {/* Header */}
      <div className="border-b border-slate-800 pb-5">
        <div className="flex items-center gap-2">
          <h1 className="text-2xl font-black text-white uppercase tracking-tight">
            THREAT INTELLIGENCE & RECONNAISSANCE MATRIX
          </h1>
          <span className="rounded bg-violet-950 px-2 py-0.5 text-[10px] font-bold text-violet-400 border border-violet-800/50">
            IOC LINKED
          </span>
        </div>
        <p className="text-xs text-slate-400 mt-1">
          Trace adversary attack propagation across enterprise boundaries and cross-reference indicators with global threat intelligence.
        </p>
      </div>

      {/* Spatial Attack Graph */}
      <NetworkTopology />

      {/* Threat Intel IOC Query Tool */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-6 rounded-2xl border border-slate-800 bg-obsidian-900/80 p-6 shadow-xl backdrop-blur-xl">
          <div className="flex items-center gap-2.5 border-b border-slate-800 pb-3">
            <Globe className="h-5 w-5 text-cyan-400" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              IOC REPUTATION & THREAT ACTOR LOOKUP
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-2">
            Verify arbitrary IPv4/IPv6 addresses, domains, or URL indicators against local threat feeds and heuristic entropy scores.
          </p>

          <div className="mt-4 flex gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
              <input
                type="text"
                value={iocQuery}
                onChange={(e) => setIocQuery(e.target.value)}
                placeholder="Enter IP address, domain, or URL path..."
                className="w-full rounded-xl border border-slate-700 bg-obsidian-950 pl-9 pr-4 py-2 text-xs font-mono font-bold text-white focus:border-cyan-400 focus:outline-none"
              />
            </div>
            <button
              onClick={handleQuery}
              className="rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 px-5 py-2 text-xs font-bold text-obsidian-950 shadow-md shadow-cyan-500/20 hover:brightness-110"
            >
              Scan IOC
            </button>
          </div>

          {/* Quick Example Pills */}
          <div className="mt-3 flex items-center gap-2 text-[11px] text-slate-400">
            <span>Examples:</span>
            <button
              onClick={() => { setIocQuery('185.220.101.5'); }}
              className="mono text-cyan-400 hover:underline"
            >
              185.220.101.5
            </button>
            <span>&bull;</span>
            <button
              onClick={() => { setIocQuery('paypal-security-update.xyz'); }}
              className="mono text-cyan-400 hover:underline"
            >
              paypal-security-update.xyz
            </button>
            <span>&bull;</span>
            <button
              onClick={() => { setIocQuery('10.0.0.5'); }}
              className="mono text-cyan-400 hover:underline"
            >
              10.0.0.5 (Clean)
            </button>
          </div>

          {/* Result Card */}
          {iocResult && (
            <div
              className={`mt-4 rounded-xl border p-4 ${
                iocResult.verdict === 'malicious'
                  ? 'border-red-500/40 bg-red-950/20 text-red-200'
                  : iocResult.verdict === 'suspicious'
                  ? 'border-amber-500/40 bg-amber-950/20 text-amber-200'
                  : 'border-emerald-500/40 bg-emerald-950/20 text-emerald-200'
              }`}
            >
              <div className="flex items-center justify-between border-b border-white/10 pb-2">
                <span className="mono text-xs font-bold text-white">{iocResult.query}</span>
                <span
                  className={`rounded px-2 py-0.5 text-[10px] font-black uppercase ${
                    iocResult.verdict === 'malicious'
                      ? 'bg-red-500 text-white'
                      : iocResult.verdict === 'suspicious'
                      ? 'bg-amber-500 text-black'
                      : 'bg-emerald-500 text-black'
                  }`}
                >
                  {iocResult.verdict} ({iocResult.score}/100)
                </span>
              </div>
              <div className="mt-2 text-xs font-bold text-white">Actor / Association: {iocResult.actor}</div>
              <p className="mt-1 text-xs text-slate-300 leading-relaxed">{iocResult.details}</p>
            </div>
          )}
        </div>

        {/* MITRE ATT&CK Matrix Reference */}
        <div className="lg:col-span-6 rounded-2xl border border-slate-800 bg-obsidian-900/80 p-6 shadow-xl backdrop-blur-xl space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              ENTERPRISE ATT&CK FRAMEWORK COVERAGE
            </h3>
            <span className="mono text-[10px] text-cyan-400">v14.1 COMPLIANT</span>
          </div>

          <div className="space-y-2.5">
            {[
              { id: 'T1110.001', name: 'Password Guessing', tactic: 'Credential Access', level: 'Critical' },
              { id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery', level: 'High' },
              { id: 'T1498.001', name: 'Direct Network Flood', tactic: 'Impact', level: 'Critical' },
              { id: 'T1048.003', name: 'Exfiltration Over Protocol', tactic: 'Exfiltration', level: 'Critical' },
              { id: 'T1566.002', name: 'Spearphishing Link / C2', tactic: 'Initial Access', level: 'High' },
            ].map((m, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between rounded-xl border border-slate-800 bg-obsidian-950 px-3.5 py-2.5 transition-all hover:border-violet-500/40"
              >
                <div className="flex items-center gap-3">
                  <span className="mono text-xs font-black text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/40">
                    {m.id}
                  </span>
                  <div>
                    <div className="text-xs font-bold text-white">{m.name}</div>
                    <div className="text-[10px] text-slate-400">Tactic: {m.tactic}</div>
                  </div>
                </div>
                <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] font-bold text-slate-300">
                  {m.level}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
