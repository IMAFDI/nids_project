export interface Event {
  id: number;
  timestamp: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  rule_triggered?: string;
  ml_score?: number;
  threat_intel_score?: number;
  country_code?: string;
  acknowledged: boolean;
  description?: string;
}

export interface Rule {
  id: number;
  name: string;
  rule_type: 'SIGNATURE' | 'RATE_LIMIT' | 'PAYLOAD_MATCH' | 'GEO_BLOCK' | 'WHITELIST';
  enabled: boolean;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  criteria: Record<string, any>;
  version: number;
  last_matched?: string;
  hit_count?: number;
}

export interface Stats {
  total_events: number;
  events_by_severity: Record<string, number>;
  events_last_24h: number;
  events_last_7d: number;
  events_last_30d: number;
  top_attackers: Array<{ src_ip: string; count: number }>;
}

export interface SystemMetrics {
  cpu_percent: number;
  memory_percent: number;
  queue_depth: number;
  packets_per_second: number;
  uptime_seconds: number;
}
