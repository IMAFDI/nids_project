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
  lifecycle_state: 'draft' | 'staging' | 'production';
  mitre_tactics?: string[];
  mitre_techniques?: string[];
  suppression_enabled?: boolean;
  suppression_window_seconds?: number;
  last_trigger_fingerprint?: string | null;
  last_trigger_at?: string | null;
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

export interface RetentionPolicy {
  id: number;
  name: string;
  scope: 'global' | 'severity' | 'tenant';
  hot_days: number;
  warm_days: number;
  cold_days: number;
  archive_enabled: boolean;
  delete_after_days: number;
  enabled: boolean;
  severity?: string | null;
  tenant_id?: string | null;
  created_at: string;
  updated_at: string;
}

export interface RetentionDryRun {
  evaluated_events: number;
  archive_candidates: number;
  delete_candidates: number;
  matched_policy_ids: number[];
}

export interface SLOSummary {
  window_minutes: number;
  ingestion_availability: number;
  event_processing_latency_ms: {
    p50: number;
    p95: number;
  };
  queue_depth_trend: {
    current: number;
    avg_5m: number;
    direction: 'rising' | 'falling' | 'stable';
    recent: number[];
  };
  connectivity: {
    broker: string;
    database: string;
    cache: string;
  };
  error_budget_remaining: number;
  snapshots_recorded: number;
  generated_at: string;
}

export interface SLOSnapshot {
  id: number;
  tenant_id?: string | null;
  ingestion_availability: number;
  latency_p50_ms: number;
  latency_p95_ms: number;
  queue_depth: number;
  queue_trend: string;
  broker_state: string;
  db_state: string;
  cache_state: string;
  error_budget_remaining: number;
  created_at: string;
}

export interface BackupOperation {
  id: number;
  operation_type: string;
  status: string;
  duration_ms?: number | null;
  artifact_path?: string | null;
  operation_metadata?: Record<string, any> | null;
  initiated_by?: string | null;
  source_ip?: string | null;
  tenant_id?: string | null;
  created_at: string;
  updated_at: string;
}

export interface UserProfile {
  id: number;
  username: string;
  email: string;
  full_name?: string | null;
  role: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  last_login?: string | null;
}

export interface CaseNote {
  id: number;
  case_id: number;
  author_user_id: number;
  note: string;
  created_at: string;
}

export interface CaseItem {
  id: number;
  title: string;
  status: 'OPEN' | 'IN_PROGRESS' | 'ON_HOLD' | 'CLOSED';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  owner_user_id?: number | null;
  created_by_user_id: number;
  created_at: string;
  updated_at: string;
  closed_at?: string | null;
}

export interface CaseDetail extends CaseItem {
  events: Event[];
  notes: CaseNote[];
}

export interface PlaybookExecution {
  id: number;
  playbook_id: number;
  event_id?: number | null;
  case_id?: number | null;
  action: string;
  status: 'success' | 'failed' | 'skipped';
  response_payload?: Record<string, any> | null;
  error_details?: string | null;
  actor?: string | null;
  actor_type: string;
  started_at: string;
  finished_at?: string | null;
  created_at: string;
}

export interface Playbook {
  id: number;
  name: string;
  description?: string | null;
  trigger_severities: string[];
  trigger_rule_ids: number[];
  trigger_event_types: string[];
  enabled: boolean;
  actions: Array<Record<string, any>>;
  last_run_at?: string | null;
  success_count: number;
  failure_count: number;
  created_at: string;
  updated_at: string;
}
