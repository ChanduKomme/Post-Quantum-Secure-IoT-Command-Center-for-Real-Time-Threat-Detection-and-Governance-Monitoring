const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8090';

export async function apiGet(path) {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) throw new Error(`${path} failed with HTTP ${res.status}`);
  return res.json();
}

export async function getOverview() {
  return apiGet('/api/overview');
}

export { API_BASE };
