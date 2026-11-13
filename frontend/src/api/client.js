import axios from 'axios';

// Create Axios client configured for FastAPI backend
const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  },
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    const errorMsg = error.response?.data?.detail || error.message || 'Network connection to backend failed';
    console.error('API Error:', errorMsg);
    return Promise.reject(error);
  }
);

export default api;

