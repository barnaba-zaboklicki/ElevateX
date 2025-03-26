const API_BASE_URL = 'https://127.0.0.1:5000/api';

// Generic fetch wrapper with error handling
export const fetchAPI = async (endpoint, options = {}) => {
    try {
        console.log(`Making request to: ${API_BASE_URL}${endpoint}`);
        console.log('Request options:', options);

        const response = await fetch(`${API_BASE_URL}${endpoint}`, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...(options.headers || {}),
            },
            credentials: 'include',
            mode: 'cors',
            referrerPolicy: 'no-referrer',
            cache: 'no-cache'
        });

        console.log('Response status:', response.status);
        console.log('Response headers:', Object.fromEntries(response.headers.entries()));

        // Try to parse the response as JSON
        let data;
        try {
            data = await response.json();
        } catch (e) {
            console.error('Failed to parse response as JSON:', e);
            throw new Error(`Failed to parse response: ${response.status} ${response.statusText}`);
        }

        if (!response.ok) {
            console.error('Response error:', data);
            throw new Error(data.message || `HTTP error! status: ${response.status}`);
        }

        console.log('Response data:', data);
        return data;
    } catch (error) {
        console.error('API Error:', error);
        if (error.message === 'Failed to fetch') {
            console.error('Network error - please check if the backend server is running');
            console.error('Backend URL:', API_BASE_URL);
        }
        throw error;
    }
};

// Health check
export const checkHealth = () => fetchAPI('/health');

// API methods
export const api = {
    // Auth methods
    auth: {
        // Register a new user
        register: async (userData) => {
            try {
                return await fetchAPI('/auth/register', {
                    method: 'POST',
                    body: JSON.stringify(userData),
                });
            } catch (error) {
                console.error('Registration error:', error);
                throw error;
            }
        },

        // Login user
        login: async (credentials) => {
            try {
                return await fetchAPI('/auth/login', {
                    method: 'POST',
                    body: JSON.stringify(credentials),
                });
            } catch (error) {
                console.error('Login error:', error);
                throw error;
            }
        },

        // Get user profile
        getProfile: async () => {
            try {
                const token = localStorage.getItem('token');
                if (!token) {
                    throw new Error('No authentication token found');
                }

                return await fetchAPI('/auth/profile', {
                    headers: {
                        'Authorization': `Bearer ${token}`,
                    },
                });
            } catch (error) {
                console.error('Profile error:', error);
                throw error;
            }
        },

        // Logout user
        logout: () => {
            localStorage.removeItem('token');
            localStorage.removeItem('user');
        },

        // Check if user is authenticated
        isAuthenticated: () => {
            return !!localStorage.getItem('token');
        },

        // Get current user
        getCurrentUser: () => {
            const userStr = localStorage.getItem('user');
            return userStr ? JSON.parse(userStr) : null;
        }
    },

    // Health check
    checkHealth: () => fetchAPI('/health'),

    // Add more API methods as needed
}; 