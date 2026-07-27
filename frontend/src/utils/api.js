const API_BASE = import.meta.env.VITE_API_BASE ?? '';

export function getToken(){
  return localStorage.getItem('devsecops_agent_token');
}

export function setToken(token){
  localStorage.setItem('devsecops_agent_token', token);
}

export function clearToken(){
  localStorage.removeItem('devsecops_agent_token');
}

function apiUrl(path){
  if(!API_BASE) return path;
  return `${API_BASE}${path}`;
}

export async function api(path, options={}){
  const headers = {'Content-Type':'application/json', ...(options.headers || {})};
  const token = getToken();
  if(token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(apiUrl(path), {...options, headers});
  const data = await res.json().catch(()=>({}));
  if(!res.ok){
    if(res.status === 401 || res.status === 403){
      clearToken();
      throw new Error(data.detail || 'Session expired or unauthorized. Please log in again.');
    }
    throw new Error(data.detail || 'Request failed');
  }
  return data;
}

export function wsUrl(path){
  if(API_BASE){
    return `${API_BASE.replace(/^http/, 'ws')}${path}`;
  }
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${protocol}//${window.location.host}${path}`;
}
