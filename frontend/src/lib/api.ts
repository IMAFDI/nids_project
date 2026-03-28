import axios from 'axios';
import {
  UserProfile,
  CaseItem,
  CaseDetail,
  Playbook,
  PlaybookExecution,
  RetentionPolicy,
  RetentionDryRun,
  SLOSummary,
  SLOSnapshot,
  BackupOperation,
} from '../types';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '/api/v1';

const api = axios.create({
  baseURL: API_BASE,
});

let authToken: string | null = localStorage.getItem('nids_token');

export const setAuthToken = (token: string | null) => {
  authToken = token;
  if (token) {
    localStorage.setItem('nids_token', token);
    api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  } else {
    localStorage.removeItem('nids_token');
    delete api.defaults.headers.common['Authorization'];
  }
};

if (authToken) {
  setAuthToken(authToken);
}

export const login = async (username: string, password: string) => {
  const response = await api.post('/auth/login', { username, password });
  setAuthToken(response.data.access_token);
  return response.data;
};

export const register = async (payload: {
  username: string;
  email: string;
  password: string;
  full_name?: string;
}) => {
  const response = await api.post('/auth/register', payload);
  return response.data;
};

export const requestPasswordReset = async (email: string) => {
  const response = await api.post('/auth/forgot-password', { email });
  return response.data;
};

export const confirmPasswordReset = async (payload: {
  email: string;
  token: string;
  new_password: string;
}) => {
  const response = await api.post('/auth/reset-password', payload);
  return response.data;
};

export const logout = () => {
  setAuthToken(null);
};

export const fetchEvents = async (page = 1, perPage = 50, filters?: any) => {
  const response = await api.get('/events', { params: { page, per_page: perPage, ...filters } });
  return response.data;
};

export const acknowledgeEvent = async (eventId: number) => {
  const response = await api.post(`/events/${eventId}/acknowledge`);
  return response.data;
};

export const fetchStats = async () => {
  const response = await api.get('/stats');
  return response.data;
};

export const fetchRules = async () => {
  const response = await api.get('/rules');
  return response.data;
};

export const fetchRulesByMitre = async (filters: { technique?: string; tactic?: string }) => {
  const response = await api.get('/rules/mitre', { params: filters });
  return response.data;
};

export const toggleRule = async (ruleId: number) => {
  const response = await api.post(`/rules/${ruleId}/toggle`);
  return response.data;
};

export const createRule = async (rule: any) => {
  const response = await api.post('/rules', rule);
  return response.data;
};

export const updateRule = async (ruleId: number, rule: any) => {
  const response = await api.put(`/rules/${ruleId}`, rule);
  return response.data;
};

export const promoteRuleLifecycle = async (ruleId: number, lifecycle_state: 'draft' | 'staging' | 'production') => {
  const response = await api.post(`/rules/${ruleId}/lifecycle`, { lifecycle_state });
  return response.data;
};

export const deleteRule = async (ruleId: number) => {
  const response = await api.delete(`/rules/${ruleId}`);
  return response.data;
};

export const fetchSystemMetrics = async () => {
  const response = await api.get('/system/metrics');
  return response.data;
};

export const fetchSLOSummary = async (windowMinutes = 15): Promise<SLOSummary> => {
  const response = await api.get('/system/slo', { params: { window_minutes: windowMinutes } });
  return response.data;
};

export const fetchSLOHistory = async (limit = 48): Promise<SLOSnapshot[]> => {
  const response = await api.get('/system/slo/history', { params: { limit } });
  return response.data;
};

export const fetchRetentionPolicies = async (): Promise<RetentionPolicy[]> => {
  const response = await api.get('/system/retention/policies');
  return response.data;
};

export const createRetentionPolicy = async (payload: {
  name: string;
  scope: 'global' | 'severity' | 'tenant';
  hot_days: number;
  warm_days: number;
  cold_days: number;
  archive_enabled: boolean;
  delete_after_days: number;
  enabled?: boolean;
  severity?: string;
}): Promise<RetentionPolicy> => {
  const response = await api.post('/system/retention/policies', payload);
  return response.data;
};

export const updateRetentionPolicy = async (id: number, payload: Partial<{
  name: string;
  scope: 'global' | 'severity' | 'tenant';
  hot_days: number;
  warm_days: number;
  cold_days: number;
  archive_enabled: boolean;
  delete_after_days: number;
  enabled: boolean;
  severity: string;
}>): Promise<RetentionPolicy> => {
  const response = await api.put(`/system/retention/policies/${id}`, payload);
  return response.data;
};

export const deleteRetentionPolicy = async (id: number) => {
  const response = await api.delete(`/system/retention/policies/${id}`);
  return response.data;
};

export const runRetentionDryRun = async (): Promise<RetentionDryRun> => {
  const response = await api.post('/system/retention/dry-run');
  return response.data;
};

export const executeRetentionMaintenance = async (payload: { apply_delete: boolean; confirm_delete: boolean }) => {
  const response = await api.post('/system/retention/execute', payload);
  return response.data;
};

export const startBackup = async (payload: {
  target?: string;
  dry_run?: boolean;
  include_events?: boolean;
  include_rules?: boolean;
  include_cases?: boolean;
}): Promise<BackupOperation> => {
  const response = await api.post('/system/backup/start', payload);
  return response.data;
};

export const fetchBackupHistory = async (limit = 50): Promise<BackupOperation[]> => {
  const response = await api.get('/system/backup/history', { params: { limit } });
  return response.data;
};

export const runBackupRestoreTest = async (payload: {
  backup_id?: number;
  artifact_path?: string;
  dry_run?: boolean;
}): Promise<BackupOperation> => {
  const response = await api.post('/system/backup/restore-test', payload);
  return response.data;
};

export const exportEvents = async (format: 'csv' | 'json') => {
  const response = await api.get('/export/events', { params: { format }, responseType: 'blob' });
  return response.data;
};

export const fetchCurrentUser = async (): Promise<UserProfile> => {
  const response = await api.get('/auth/me');
  return response.data;
};

export const updateCurrentUser = async (payload: { email?: string; full_name?: string }): Promise<UserProfile> => {
  const response = await api.put('/auth/me', payload);
  return response.data;
};

export const changePassword = async (payload: { current_password: string; new_password: string }) => {
  const response = await api.post('/auth/change-password', payload);
  return response.data;
};

export const fetchCases = async (
  page = 1,
  perPage = 50,
  filters?: { status?: string; severity?: string; owner_user_id?: number }
): Promise<{ cases: CaseItem[]; total: number; limit: number; offset: number }> => {
  const response = await api.get('/cases', { params: { page, per_page: perPage, ...filters } });
  return response.data;
};

export const createCase = async (payload: {
  title: string;
  severity?: string;
  priority?: string;
  owner_user_id?: number | null;
  event_ids?: number[];
}): Promise<CaseItem> => {
  const response = await api.post('/cases', payload);
  return response.data;
};

export const fetchCaseDetail = async (id: number): Promise<CaseDetail> => {
  const response = await api.get(`/cases/${id}`);
  return response.data;
};

export const updateCase = async (
  id: number,
  payload: { title?: string; status?: string; priority?: string; owner_user_id?: number | null }
): Promise<CaseItem> => {
  const response = await api.put(`/cases/${id}`, payload);
  return response.data;
};

export const addCaseNote = async (id: number, note: string) => {
  const response = await api.post(`/cases/${id}/notes`, { note });
  return response.data;
};

export const linkCaseEvent = async (id: number, eventId: number) => {
  const response = await api.post(`/cases/${id}/events/${eventId}`);
  return response.data;
};

export const unlinkCaseEvent = async (id: number, eventId: number) => {
  const response = await api.delete(`/cases/${id}/events/${eventId}`);
  return response.data;
};

export const fetchPlaybooks = async (enabled?: boolean): Promise<Playbook[]> => {
  const response = await api.get('/playbooks', { params: enabled === undefined ? undefined : { enabled } });
  return response.data;
};

export const createPlaybook = async (payload: {
  name: string;
  description?: string;
  trigger_severities?: string[];
  trigger_rule_ids?: number[];
  trigger_event_types?: string[];
  enabled?: boolean;
  actions?: Array<Record<string, any>>;
}): Promise<Playbook> => {
  const response = await api.post('/playbooks', payload);
  return response.data;
};

export const getPlaybook = async (id: number): Promise<Playbook> => {
  const response = await api.get(`/playbooks/${id}`);
  return response.data;
};

export const updatePlaybook = async (
  id: number,
  payload: Partial<{
    name: string;
    description: string;
    trigger_severities: string[];
    trigger_rule_ids: number[];
    trigger_event_types: string[];
    enabled: boolean;
    actions: Array<Record<string, any>>;
  }>
): Promise<Playbook> => {
  const response = await api.put(`/playbooks/${id}`, payload);
  return response.data;
};

export const deletePlaybook = async (id: number) => {
  const response = await api.delete(`/playbooks/${id}`);
  return response.data;
};

export const togglePlaybook = async (id: number): Promise<Playbook> => {
  const response = await api.post(`/playbooks/${id}/toggle`);
  return response.data;
};

export const testPlaybook = async (id: number, sample_payload: Record<string, any>) => {
  const response = await api.post(`/playbooks/${id}/test`, { sample_payload });
  return response.data;
};

export const fetchPlaybookExecutions = async (
  id: number,
  page = 1,
  perPage = 20
): Promise<{ executions: PlaybookExecution[]; total: number; limit: number; offset: number }> => {
  const response = await api.get(`/playbooks/${id}/executions`, { params: { page, per_page: perPage } });
  return response.data;
};

export const executePlaybooksForEvent = async (eventId: number) => {
  const response = await api.post(`/playbooks/execute/event/${eventId}`);
  return response.data;
};

export const executePlaybooksForCase = async (caseId: number) => {
  const response = await api.post(`/playbooks/execute/case/${caseId}`);
  return response.data;
};

export const upsertTicketIntegration = async (payload: { provider_type: string; enabled: boolean; config: Record<string, any> }) => {
  const response = await api.post('/playbooks/integrations/ticket', payload);
  return response.data;
};

export const fetchTicketIntegration = async (providerType: string) => {
  const response = await api.get(`/playbooks/integrations/ticket/${providerType}`);
  return response.data;
};

export default api;
