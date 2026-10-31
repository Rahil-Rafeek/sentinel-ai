import React, { useState, useMemo } from 'react';
import { ThreatEvent, ThreatCategory, Severity } from '../types';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Cpu, 
  Zap, 
  Terminal, 
  ShieldAlert, 
  Sliders, 
  Play, 
  CheckCircle2, 
  Sparkles, 
  Activity, 
  ExternalLink,
  Flame,
  Globe,
  Radio,
  Server,
  Lock
} from 'lucide-react';

interface DetectionPlaygroundProps {
  onInjectThreat: (event: ThreatEvent) => void;
  onOpenDrawer: (event: ThreatEvent) => void;
}

type AttackPreset = 
  | 'Brute-Force Login'
  | 'Port Scanning'
  | 'Abnormally High Traffic'
  | 'Suspicious User Behaviour'
  | 'Malicious URL/Indicator';

export const DetectionPlayground: React.FC<DetectionPlaygroundProps> = ({
  onInjectThreat,
  onOpenDrawer,
}) => {
  const [selectedPreset, setSelectedPreset] = useState<AttackPreset>('Brute-Force Login');
  
  // Dynamic parameters
  const [failedAttempts, setFailedAttempts] = useState<number>(42);
  const [timeWindowSec, setTimeWindowSec] = useState<number>(30);
  const [targetUsername, setTargetUsername] = useState<string>('root');
  
  const [portsScanned, setPortsScanned] = useState<number>(450);
  const [scanDurationSec, setScanDurationSec] = useState<number>(12);
  const [scanType, setScanType] = useState<string>('SYN Stealth');
  
  const [packetRateKpps, setPacketRateKpps] = useState<number>(185);
  const [floodProtocol, setFloodProtocol] = useState<string>('UDP');
  
  const [transferVolumeMb, setTransferVolumeMb] = useState<number>(850);
  const [shannonEntropy, setShannonEntropy] = useState<number>(5.8);
  const [exfilProtocol, setExfilProtocol] = useState<string>('HTTPS (Port 443)');
  
  const [rawUrlString, setRawUrlString] = useState<string>(
    'https://login-vault-secure-sso.auth-verify.xyz/session-v3/auth?token=9x98a7sd6f51c'
  );
  
  const [injectedBanner, setInjectedBanner] = useState<ThreatEvent | null>(null);

  // Calculate Shannon entropy of the URL string dynamically
  const calculatedUrlEntropy = useMemo(() => {
    if (!rawUrlString || rawUrlString.length === 0) return 0;
    const freq: Record<string, number> = {};
    for (const char of rawUrlString) {
      freq[char] = (freq[char] || 0) + 1;
    }
    const len = rawUrlString.length;
    let entropy = 0;
    for (const char in freq) {
      const p = freq[char] / len;
      entropy -= p * Math.log2(p);
    }
    return parseFloat(entropy.toFixed(3));
  }, [rawUrlString]);

  // Live Simulated ML Inference evaluation
  const liveInference = useMemo(() => {
    let category: ThreatCategory = 'Benign';
    let severity: Severity = 'Low';
    let rfConfidence = 0.92;
    let lrConfidence = 0.88;
    let threatScore = 20;
    let mitreId = 'T1000';
    let mitreName = 'General Reconnaissance';
    let mitreTactic = 'Reconnaissance';
    let evidence = '';
    let recommendation = '';
    let srcPort = 49152 + Math.floor(Math.random() * 5000);
    let dstPort = 80;

    switch (selectedPreset) {
      case 'Brute-Force Login': {
        category = 'Brute-Force Login';
        const rate = failedAttempts / Math.max(1, timeWindowSec);
        if (failedAttempts > 30 || rate > 1.2) {
          severity = 'Critical';
          threatScore = 96;
          rfConfidence = 0.984;
          lrConfidence = 0.952;
        } else if (failedAttempts > 10) {
          severity = 'High';
          threatScore = 82;
          rfConfidence = 0.931;
          lrConfidence = 0.895;
        } else {
          severity = 'Medium';
          threatScore = 55;
          rfConfidence = 0.82;
          lrConfidence = 0.78;
        }
        dstPort = targetUsername === 'root' ? 22 : 443;
        mitreId = 'T1110.001';
        mitreName = 'Brute Force: Password Guessing';
        mitreTactic = 'Credential Access';
        evidence = `Rapid sequence of ${failedAttempts} failed authentications targeting account '${targetUsername}' across ${timeWindowSec}s (${(failedAttempts / timeWindowSec).toFixed(1)} attempts/sec).`;
        recommendation = `Trigger IP blacklist, implement exponential rate-limiting or CAPTCHA, and enforce mandatory multi-factor authentication for '${targetUsername}'.`;
        break;
      }

      case 'Port Scanning': {
        category = 'Port Scanning';
        const rate = portsScanned / Math.max(1, scanDurationSec);
        if (portsScanned > 300 || rate > 20) {
          severity = 'High';
          threatScore = 88;
          rfConfidence = 0.976;
          lrConfidence = 0.938;
        } else {
          severity = 'Medium';
          threatScore = 64;
          rfConfidence = 0.89;
          lrConfidence = 0.84;
        }
        dstPort = 1;
        mitreId = 'T1046';
        mitreName = 'Network Service Discovery';
        mitreTactic = 'Discovery';
        evidence = `Host sweep across ${portsScanned} distinct ports utilizing ${scanType} packets within ${scanDurationSec}s (${rate.toFixed(1)} probes/sec).`;
        recommendation = `Engage stateful firewall TCP reset response, enable aggressive SYN flood throttling, and quarantine attacker subnet.`;
        break;
      }

      case 'Abnormally High Traffic': {
        category = 'Abnormally High Traffic';
        if (packetRateKpps > 150) {
          severity = 'Critical';
          threatScore = 98;
          rfConfidence = 0.991;
          lrConfidence = 0.967;
        } else if (packetRateKpps > 50) {
          severity = 'High';
          threatScore = 84;
          rfConfidence = 0.94;
          lrConfidence = 0.91;
        } else {
          severity = 'Medium';
          threatScore = 60;
          rfConfidence = 0.86;
          lrConfidence = 0.82;
        }
        dstPort = 80;
        mitreId = 'T1498.001';
        mitreName = 'Direct Volumetric Flood';
        mitreTactic = 'Impact';
        evidence = `Volumetric ingress spike reaching ${packetRateKpps}k pkts/sec over ${floodProtocol} protocol, degrading router buffer headroom.`;
        recommendation = `Activate Edge Anycast scrubbing centers, push automated BGP FlowSpec blackhole for ingress prefix.`;
        break;
      }

      case 'Suspicious User Behaviour': {
        category = 'Suspicious User Behaviour';
        if (transferVolumeMb > 500 || shannonEntropy > 6.0) {
          severity = 'Critical';
          threatScore = 94;
          rfConfidence = 0.965;
          lrConfidence = 0.932;
        } else {
          severity = 'High';
          threatScore = 79;
          rfConfidence = 0.902;
          lrConfidence = 0.865;
        }
        dstPort = 443;
        mitreId = 'T1048.003';
        mitreName = 'Exfiltration Over Alternative Protocol';
        mitreTactic = 'Exfiltration';
        evidence = `High-volume encrypted stream of ${transferVolumeMb} MB transferred to untrusted egress node with elevated Shannon entropy of ${shannonEntropy}.`;
        recommendation = `Sever active TCP session via EDR kill-switch, isolate host workstation, and rotate tenant API credentials.`;
        break;
      }

      case 'Malicious URL/Indicator': {
        category = 'Malicious URL/Indicator';
        const isSuspiciousTLD = rawUrlString.includes('.xyz') || rawUrlString.includes('.top') || rawUrlString.includes('.ru');
        if (calculatedUrlEntropy > 4.5 || isSuspiciousTLD || rawUrlString.length > 70) {
          severity = 'Critical';
          threatScore = 95;
          rfConfidence = 0.987;
          lrConfidence = 0.949;
        } else {
          severity = 'Medium';
          threatScore = 62;
          rfConfidence = 0.85;
          lrConfidence = 0.81;
        }
        dstPort = 443;
        mitreId = 'T1071.001';
        mitreName = 'Application Layer Protocol: Web Protocols';
        mitreTactic = 'Command and Control';
        evidence = `URI exhibits high structural entropy (${calculatedUrlEntropy}), lexical markers matching weaponized credential harvesting phishing kits.`;
        recommendation = `Push domain-level sinkhole entry to internal DNS resolvers, purge corporate email inboxes, and reset impacted browser sessions.`;
        break;
      }
    }

    return {
      category,
      severity,
      threatScore,
      rfConfidence,
      lrConfidence,
      mitreId,
      mitreName,
      mitreTactic,
      evidence,
      recommendation,
      srcPort,
      dstPort,
    };
  }, [
    selectedPreset,
    failedAttempts,
    timeWindowSec,
    targetUsername,
    portsScanned,
    scanDurationSec,
    scanType,
    packetRateKpps,
    floodProtocol,
    transferVolumeMb,
    shannonEntropy,
    rawUrlString,
    calculatedUrlEntropy,
  ]);

  const handleInject = () => {
    const syntheticId = `SNTL-${Math.floor(1000 + Math.random() * 9000)}`;
    const newEvent: ThreatEvent = {
      id: syntheticId,
      timestamp: new Date().toISOString(),
      category: liveInference.category,
      severity: liveInference.severity,
      confidence: liveInference.rfConfidence,
      srcIp: `198.51.100.${Math.floor(10 + Math.random() * 200)}`,
      srcPort: liveInference.srcPort,
      dstIp: '10.0.4.15',
      dstPort: liveInference.dstPort,
      protocol: selectedPreset === 'Port Scanning' ? 'TCP' : selectedPreset === 'Abnormally High Traffic' ? floodProtocol : 'TCP',
      durationSec: timeWindowSec || scanDurationSec || 5,
      bytesSent: (transferVolumeMb * 1024 * 1024) || (failedAttempts * 840) || (packetRateKpps * 1000),
      bytesReceived: 1024,
      packetsSent: (packetRateKpps * 1000) || portsScanned || failedAttempts * 3,
      packetsReceived: 24,
      detectionMethod: `Dual-Ensemble ML (RF ${Math.round(liveInference.rfConfidence * 100)}% + LR ${Math.round(liveInference.lrConfidence * 100)}%)`,
      evidence: liveInference.evidence,
      recommendedAction: liveInference.recommendation,
      status: 'Open',
      mitreId: liveInference.mitreId,
      mitreName: liveInference.mitreName,
      mitreTactic: liveInference.mitreTactic,
      radarAngle: Math.floor(Math.random() * 360),
      radarRadius: liveInference.severity === 'Critical' ? 0.35 : liveInference.severity === 'High' ? 0.6 : 0.85,
    };

    onInjectThreat(newEvent);
    setInjectedBanner(newEvent);
    setTimeout(() => setInjectedBanner(null), 8000);
  };

  return (
    <div className="space-y-8 pb-16">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <div className="flex items-center gap-2">
            <span className="flex h-2 w-2 rounded-full bg-cyan-400 animate-ping" />
            <span className="mono text-xs font-bold text-cyan-400 uppercase tracking-widest">
              INTERACTIVE ATTACK SIMULATION WORKSPACE
            </span>
            <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] font-semibold text-slate-400">
              SIMULATED TELEMETRY
            </span>
          </div>
          <h1 className="text-3xl font-black tracking-tight text-white mt-1">
            Detection Playground & Scenario Sandbox
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Simulate realistic attack telemetry against the dual Random Forest and Logistic Regression classification engines. 
            Adjust threat parameters live to observe algorithmic confidence shifts and inject synthetic vectors into the live incident pipeline.
          </p>
        </div>

        {/* Live Attack Injection CTA */}
        <motion.button
          whileHover={{ scale: 1.03 }}
          whileTap={{ scale: 0.97 }}
          onClick={handleInject}
          className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-red-600 via-rose-600 to-amber-600 px-6 py-3.5 text-sm font-black text-white shadow-xl shadow-red-500/25 hover:shadow-red-500/40 transition-all border border-red-400/30"
        >
          <Flame className="h-5 w-5 animate-bounce" />
          <span>INJECT SYNTHETIC ATTACK VECTOR</span>
        </motion.button>
      </div>

      {/* Success Injection Banner */}
      <AnimatePresence>
        {injectedBanner && (
          <motion.div
            initial={{ opacity: 0, y: -20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -20, scale: 0.95 }}
            className="rounded-xl border border-red-500/50 bg-red-950/40 p-4 shadow-xl shadow-red-500/10 flex items-center justify-between backdrop-blur-md"
          >
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-red-500/20 text-red-400">
                <CheckCircle2 className="h-6 w-6" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold text-red-400 uppercase tracking-wider">
                    ATTACK INJECTED INTO LIVE STREAM
                  </span>
                  <span className="mono rounded bg-red-900/40 px-2 py-0.5 text-xs font-black text-red-200">
                    {injectedBanner.id}
                  </span>
                </div>
                <p className="text-xs text-slate-300 mt-0.5">
                  {injectedBanner.category} ({injectedBanner.severity}) has been broadcast to the 360° Threat Radar, Event Stream, and SOC Alert Queue.
                </p>
              </div>
            </div>

            <button
              onClick={() => onOpenDrawer(injectedBanner)}
              className="flex items-center gap-1.5 rounded-lg border border-red-500/40 bg-red-900/30 px-3 py-1.5 text-xs font-bold text-red-200 hover:bg-red-800/40"
            >
              <span>Inspect in Drawer</span>
              <ExternalLink className="h-3 w-3" />
            </button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Preset Selector Ribbon */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { id: 'Brute-Force Login', label: 'Brute-Force Login', icon: Lock, desc: 'Credential Stuffing' },
          { id: 'Port Scanning', label: 'Port Scanning', icon: Radio, desc: 'Network Sweep' },
          { id: 'Abnormally High Traffic', label: 'High Traffic Flood', icon: Activity, desc: 'Volumetric DDoS' },
          { id: 'Suspicious User Behaviour', label: 'Data Exfiltration', icon: Server, desc: 'Anomalous Egress' },
          { id: 'Malicious URL/Indicator', label: 'Malicious URL', icon: Globe, desc: 'C2 / Phishing URL' },
        ].map((item) => {
          const Icon = item.icon;
          const isSelected = selectedPreset === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setSelectedPreset(item.id as AttackPreset)}
              className={`relative rounded-xl border p-4 text-left transition-all ${
                isSelected
                  ? 'border-cyan-400 bg-cyan-950/20 shadow-lg shadow-cyan-500/20'
                  : 'border-slate-800 bg-obsidian-900/60 hover:border-slate-700 hover:bg-obsidian-900'
              }`}
            >
              {isSelected && (
                <motion.div
                  layoutId="presetGlow"
                  className="absolute inset-0 rounded-xl border-2 border-cyan-400/80 pointer-events-none"
                />
              )}
              <div className="flex items-center justify-between mb-2">
                <Icon className={`h-5 w-5 ${isSelected ? 'text-cyan-400' : 'text-slate-400'}`} />
                {isSelected && (
                  <span className="flex h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
                )}
              </div>
              <div className="text-xs font-black text-white">{item.label}</div>
              <div className="text-[10px] text-slate-400 mt-0.5">{item.desc}</div>
            </button>
          );
        })}
      </div>

      {/* Main Sandbox Grid: Left = Parameter Synthesizer, Right = Real-Time AI Inference Result */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Interactive Telemetry Controls */}
        <div className="lg:col-span-7 rounded-2xl border border-slate-800 bg-obsidian-900/70 p-6 backdrop-blur-xl">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-6">
            <div className="flex items-center gap-2">
              <Sliders className="h-5 w-5 text-cyan-400" />
              <h2 className="text-base font-bold text-white">Synthesize Threat Parameters</h2>
            </div>
            <span className="text-xs text-slate-400 mono">MODE: DYNAMIC_SIMULATOR</span>
          </div>

          {/* Scenario Specific Controls */}
          {selectedPreset === 'Brute-Force Login' && (
            <div className="space-y-6">
              <div>
                <div className="flex justify-between text-xs mb-2">
                  <span className="text-slate-300 font-medium">Failed Authentication Bursts</span>
                  <span className="mono font-bold text-cyan-400">{failedAttempts} attempts</span>
                </div>
                <input
                  type="range"
                  min="2"
                  max="120"
                  value={failedAttempts}
                  onChange={(e) => setFailedAttempts(Number(e.target.value))}
                  className="w-full accent-cyan-400 bg-slate-800 h-2 rounded-lg cursor-pointer"
                />
                <div className="flex justify-between text-[10px] text-slate-400 mt-1">
                  <span>2 attempts (Low)</span>
                  <span>40 attempts (Threshold)</span>
                  <span>120 attempts (Critical Burst)</span>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-xs mb-2">
                  <span className="text-slate-300 font-medium">Burst Window Duration</span>
                  <span className="mono font-bold text-cyan-400">{timeWindowSec} seconds</span>
                </div>
                <input
                  type="range"
                  min="5"
                  max="180"
                  value={timeWindowSec}
                  onChange={(e) => setTimeWindowSec(Number(e.target.value))}
                  className="w-full accent-cyan-400 bg-slate-800 h-2 rounded-lg cursor-pointer"
                />
                <div className="flex justify-between text-[10px] text-slate-400 mt-1">
                  <span>5s (Rapid Fire)</span>
                  <span>60s (Medium)</span>
                  <span>180s (Low & Slow)</span>
                </div>
              </div>

              <div>
                <label className="text-xs font-medium text-slate-300 block mb-2">Target Account Identity</label>
                <div className="grid grid-cols-4 gap-2">
                  {['root', 'admin', 'service-account', 'guest'].map((user) => (
                    <button
                      key={user}
                      onClick={() => setTargetUsername(user)}
                      className={`rounded-lg border px-3 py-2 text-xs font-bold mono transition-all ${
                        targetUsername === user
                          ? 'border-cyan-400 bg-cyan-950/40 text-cyan-200'
                          : 'border-slate-800 bg-obsidian-950 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      {user}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {selectedPreset === 'Port Scanning' && (
            <div className="space-y-6">
              <div>
                <div className="flex justify-between text-xs mb-2">
                  <span className="text-slate-300 font-medium">Distinct Destination Ports Scanned</span>
                  <span className="mono font-bold text-cyan-400">{portsScanned} ports</span>
                </div>
                <input
                  type="range"
                  min="5"
                  max="1024"
                  value={portsScanned}
                  onChange={(e) => setPortsScanned(Number(e.target.value))}
                  className="w-full accent-cyan-400 bg-slate-800 h-2 rounded-lg cursor-pointer"
                />
                <div className="flex justify-between text-[10px] text-slate-400 mt-1">
                  <span>5 ports (Targeted)</span>
                  <span>250 ports (Subnet Sweep)</span>
                  <span>1024 ports (Full Well-Known)</span>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-xs mb-2">
                  <span className="text-slate-300 font-medium">Scan Elapsed Duration</span>
                  <span className="mono font-bold text-cyan-400">{scanDurationSec}s</span>
                </div>
                <input
                  type="range"
                  min="1"
                  max="60"
                  value={scanDurationSec}
                  onChange={(e) => setScanDurationSec(Number(e.target.value))}
                  className="w-full accent-cyan-400 bg-slate-800 h-2 rounded-lg cursor-pointer"
                />
              </div>

              <div>
                <label className="text-xs font-medium text-slate-300 block mb-2">Probing Mechanism</label>
                <div className="grid grid-cols-3 gap-2">
                  {['SYN Stealth', 'FIN/NULL Scan', 'Full TCP Connect'].map((st) => (
                    <button
                      key={st}
                      onClick={() => setScanType(st)}
                      className={`rounded-lg border px-3 py-2 text-xs font-bold mono transition-all ${
                        scanType === st
                          ? 'border-cyan-400 bg-cyan-950/40 text-cyan-200'
                          : 'border-slate-800 bg-obsidian-950 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {selectedPreset === 'Abnormally High Traffic' && (
            <div className="space-y-6">
              <div>
                <div className="flex justify-between text-xs mb-2">
                  <span className="text-slate-300 font-medium">Ingress Packet Velocity</span>
                  <span className="mono font-bold text-cyan-400">{packetRateKpps}k pkts/sec</span>
                </div>
                <input
                  type="range"
                  min="10"
                  max="500"
                  value={packetRateKpps}
                  onChange={(e) => setPacketRateKpps(Number(e.target.value))}
                  className="w-full accent-cyan-400 bg-slate-800 h-2 rounded-lg cursor-pointer"
                />
                <div className="flex justify-between text-[10px] text-slate-400 mt-1">
                  <span>10k (Baseline)</span>
                  <span>150k (Severe Flood)</span>
                  <span>500k (Saturating Line-Rate)</span>
                </div>
              </div>

              <div>
                <label className="text-xs font-medium text-slate-300 block mb-2">Flood Vector Protocol</label>
                <div className="grid grid-cols-4 gap-2">
                  {['UDP', 'ICMP', 'TCP SYN', 'DNS Amp'].map((proto) => (
                    <button
                      key={proto}
                      onClick={() => setFloodProtocol(proto)}
                      className={`rounded-lg border px-3 py-2 text-xs font-bold mono transition-all ${
                        floodProtocol === proto
                          ? 'border-cyan-400 bg-cyan-950/40 text-cyan-200'
                          : 'border-slate-800 bg-obsidian-950 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      {proto}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {selectedPreset === 'Suspicious User Behaviour' && (
            <div className="space-y-6">
              <div>
                <div className="flex justify-between text-xs mb-2">
                  <span className="text-slate-300 font-medium">Cumulative Egress Data Volume</span>
                  <span className="mono font-bold text-cyan-400">{transferVolumeMb} MB</span>
                </div>
                <input
                  type="range"
                  min="20"
                  max="2500"
                  value={transferVolumeMb}
                  onChange={(e) => setTransferVolumeMb(Number(e.target.value))}
                  className="w-full accent-cyan-400 bg-slate-800 h-2 rounded-lg cursor-pointer"
                />
              </div>

              <div>
                <div className="flex justify-between text-xs mb-2">
                  <span className="text-slate-300 font-medium">Calculated Payload Shannon Entropy</span>
                  <span className="mono font-bold text-cyan-400">{shannonEntropy} bits/byte</span>
                </div>
                <input
                  type="range"
                  min="2.0"
                  max="8.0"
                  step="0.1"
                  value={shannonEntropy}
                  onChange={(e) => setShannonEntropy(Number(e.target.value))}
                  className="w-full accent-cyan-400 bg-slate-800 h-2 rounded-lg cursor-pointer"
                />
                <div className="flex justify-between text-[10px] text-slate-400 mt-1">
                  <span>3.0 (Plaintext JSON/XML)</span>
                  <span>5.8 (Compressed Archive)</span>
                  <span>7.9 (High-Entropy Encrypted/Packed)</span>
                </div>
              </div>
            </div>
          )}

          {selectedPreset === 'Malicious URL/Indicator' && (
            <div className="space-y-6">
              <div>
                <label className="text-xs font-medium text-slate-300 block mb-2">Raw Suspect URI String</label>
                <textarea
                  value={rawUrlString}
                  onChange={(e) => setRawUrlString(e.target.value)}
                  rows={3}
                  className="w-full rounded-lg border border-slate-700 bg-obsidian-950 p-3 mono text-xs text-cyan-300 focus:border-cyan-400 focus:outline-none"
                />
              </div>

              <div className="rounded-xl border border-slate-800 bg-obsidian-950 p-4">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-400">Calculated Shannon Entropy of String:</span>
                  <span className="mono font-bold text-cyan-400 text-sm">{calculatedUrlEntropy}</span>
                </div>
                <div className="mt-2 h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-emerald-500 via-amber-500 to-rose-500 transition-all duration-300"
                    style={{ width: `${Math.min(100, (calculatedUrlEntropy / 8) * 100)}%` }}
                  />
                </div>
                <div className="flex justify-between text-[10px] text-slate-400 mt-1">
                  <span>Low &lt;3.5</span>
                  <span>Medium 3.5 - 4.5</span>
                  <span>High Suspicion &gt;4.5</span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Right Column: Real-Time AI Inference Verdict */}
        <div className="lg:col-span-5 space-y-6">
          <div className="rounded-2xl border border-slate-800 bg-obsidian-900/80 p-6 backdrop-blur-xl relative overflow-hidden">
            {/* Ambient Corner Glow */}
            <div className="absolute -top-12 -right-12 h-32 w-32 rounded-full bg-cyan-500/10 blur-2xl pointer-events-none" />

            <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
              <div className="flex items-center gap-2">
                <Cpu className="h-5 w-5 text-cyan-400" />
                <h3 className="text-sm font-bold text-white">Live AI Inference Engine</h3>
              </div>
              <span className="rounded bg-cyan-950/80 border border-cyan-500/30 px-2 py-0.5 text-[10px] font-bold text-cyan-300 mono">
                4.2ms INFERENCE
              </span>
            </div>

            {/* Severity Rating & Threat Score */}
            <div className="rounded-xl border border-slate-800 bg-obsidian-950 p-4 mb-4">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-[10px] font-bold text-slate-400 uppercase">CLASSIFICATION SEVERITY</span>
                  <div className="flex items-center gap-2 mt-1">
                    <span className={`text-xl font-black ${
                      liveInference.severity === 'Critical' ? 'text-red-400' :
                      liveInference.severity === 'High' ? 'text-amber-400' :
                      liveInference.severity === 'Medium' ? 'text-yellow-400' : 'text-emerald-400'
                    }`}>
                      {liveInference.severity.toUpperCase()}
                    </span>
                    <span className="mono text-xs text-slate-400">Score: {liveInference.threatScore}/100</span>
                  </div>
                </div>

                <div className="text-right">
                  <span className="text-[10px] font-bold text-slate-400 uppercase">PREDICTED CATEGORY</span>
                  <div className="text-xs font-bold text-white mt-1">{liveInference.category}</div>
                </div>
              </div>

              {/* Threat Score Progress Gauge */}
              <div className="mt-3 h-2 w-full bg-slate-800 rounded-full overflow-hidden">
                <motion.div
                  initial={false}
                  animate={{ width: `${liveInference.threatScore}%` }}
                  transition={{ duration: 0.4 }}
                  className={`h-full ${
                    liveInference.threatScore > 85 ? 'bg-gradient-to-r from-amber-500 to-red-500' :
                    liveInference.threatScore > 60 ? 'bg-gradient-to-r from-yellow-500 to-amber-500' :
                    'bg-gradient-to-r from-emerald-500 to-cyan-500'
                  }`}
                />
              </div>
            </div>

            {/* Dual Model Confidence Comparison */}
            <div className="grid grid-cols-2 gap-3 mb-4">
              <div className="rounded-lg border border-slate-800 bg-obsidian-950 p-3">
                <div className="flex justify-between items-center text-xs mb-1">
                  <span className="text-slate-400 font-semibold">Random Forest</span>
                  <span className="mono font-bold text-cyan-400">
                    {(liveInference.rfConfidence * 100).toFixed(1)}%
                  </span>
                </div>
                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-cyan-400 transition-all duration-300"
                    style={{ width: `${liveInference.rfConfidence * 100}%` }}
                  />
                </div>
                <span className="text-[10px] text-slate-400 mt-1 block">Decision Trees (n=100)</span>
              </div>

              <div className="rounded-lg border border-slate-800 bg-obsidian-950 p-3">
                <div className="flex justify-between items-center text-xs mb-1">
                  <span className="text-slate-400 font-semibold">Logistic Reg.</span>
                  <span className="mono font-bold text-violet-400">
                    {(liveInference.lrConfidence * 100).toFixed(1)}%
                  </span>
                </div>
                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-violet-400 transition-all duration-300"
                    style={{ width: `${liveInference.lrConfidence * 100}%` }}
                  />
                </div>
                <span className="text-[10px] text-slate-400 mt-1 block">Multinomial Logit Baseline</span>
              </div>
            </div>

            {/* MITRE Technique Card */}
            <div className="rounded-lg border border-violet-500/30 bg-violet-950/20 p-3.5 mb-4">
              <div className="flex items-center justify-between text-xs font-bold text-violet-300 mb-1">
                <span>MITRE ATT&CK CORRELATION</span>
                <span className="mono rounded bg-violet-900/40 px-1.5 py-0.5 text-[10px] text-violet-200">
                  {liveInference.mitreId}
                </span>
              </div>
              <div className="text-xs font-bold text-white">{liveInference.mitreName}</div>
              <div className="text-[11px] text-slate-400 mt-0.5">Tactic: {liveInference.mitreTactic}</div>
            </div>

            {/* Inferred Evidence Summary */}
            <div className="rounded-lg border border-slate-800 bg-obsidian-950 p-3.5 text-xs">
              <span className="text-[10px] font-bold text-slate-400 uppercase block mb-1">
                EVIDENCE RATIONALE
              </span>
              <p className="text-slate-300 leading-relaxed text-[11px]">{liveInference.evidence}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
