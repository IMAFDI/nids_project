import axios from 'axios';

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

export const deleteRule = async (ruleId: number) => {
  const response = await api.delete(`/rules/${ruleId}`);
  return response.data;
};

export const fetchSystemMetrics = async () => {
  const response = await api.get('/system/metrics');
  return response.data;
};

export const exportEvents = async (format: 'csv' | 'json') => {
  const response = await api.get('/export/events', { params: { format }, responseType: 'blob' });
  return response.data;
};

export default api;
