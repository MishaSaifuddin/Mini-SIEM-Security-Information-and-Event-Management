import api from './api';

export const authService = {
  login: (username, password) => api.post('/auth/login', { username, password }),
  register: (data) => api.post('/auth/register', data),
  getMe: () => api.get('/auth/me'),
};

export const dashboardService = {
  getSummary: (hours = 24) => api.get('/dashboard/summary', { params: { hours } }),
};

export const eventService = {
  getEvents: (params) => api.get('/events/', { params }),
  getEvent: (id) => api.get(`/events/${id}`),
  getStats: (hours = 24) => api.get('/events/stats', { params: { hours } }),
  getSources: () => api.get('/events/sources'),
};

export const alertService = {
  getAlerts: (params) => api.get('/alerts/', { params }),
  getStats: (hours = 24) => api.get('/alerts/stats', { params: { hours } }),
  getAlert: (id) => api.get(`/alerts/${id}`),
  updateAlert: (id, data) => api.put(`/alerts/${id}`, data),
  getRelatedEvents: (id) => api.post(`/alerts/${id}/related-events`),
};

export const ruleService = {
  getRules: () => api.get('/rules/'),
  getRule: (id) => api.get(`/rules/${id}`),
  createRule: (data) => api.post('/rules/', data),
  updateRule: (id, data) => api.put(`/rules/${id}`, data),
  deleteRule: (id) => api.delete(`/rules/${id}`),
  testRule: (data) => api.post('/rules/test', data),
  importSigma: (data) => api.post('/rules/sigma', data),
};

export const sourceService = {
  getSources: () => api.get('/sources/'),
  createSource: (data) => api.post('/sources/', data),
  updateSource: (id, data) => api.put(`/sources/${id}`, data),
  deleteSource: (id) => api.delete(`/sources/${id}`),
};
