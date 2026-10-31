export type ThreatCategory = 
  | 'Brute-Force Login'
  | 'Port Scanning'
  | 'Abnormally High Traffic'
  | 'Suspicious User Behaviour'
  | 'Malicious URL/Indicator'
  | 'Benign';

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

export type AlertStatus = 'Open' | 'Investigating' | 'Resolved' | 'False Positive';

export interface ThreatEvent {
  id: string;
  timestamp: string;
  category: ThreatCategory;
  severity: Severity;
  confidence: number;
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  protocol: string;
  durationSec: number;
  bytesSent: number;
  bytesReceived: number;
  packetsSent: number;
  packetsReceived: number;
  detectionMethod: string;
  evidence: string;
  recommendedAction: string;
  status: AlertStatus;
  analystNotes?: string;
  mitreId: string;
  mitreName: string;
  mitreTactic: string;
  radarAngle: number;
  radarRadius: number;
}

export interface NetworkNode {
  id: string;
  label: string;
  type: 'attacker' | 'gateway' | 'target' | 'internal';
  status: 'compromised' | 'active' | 'warning' | 'normal';
  x: number;
  y: number;
  ip: string;
  threatCount: number;
}

export interface NetworkLink {
  source: string;
  target: string;
  severity: Severity;
  flowCount: number;
  category: ThreatCategory;
}

export interface SystemTelemetry {
  eventRate: number;
  activeFlows: number;
  threatScore: number;
  postureLevel: 'DEFCON 1' | 'DEFCON 2' | 'DEFCON 3' | 'DEFCON 4' | 'DEFCON 5';
  pipelineStage: string;
  totalThreats: number;
  criticalCount: number;
  highCount: number;
}
