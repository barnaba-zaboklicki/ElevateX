import { fetchAPI } from './api.js';

const AUTH_BASE_URL = '/auth';

const authService = {
    // Register a new user
    register: async (userData) => {
        try {
            return await fetchAPI(`${AUTH_BASE_URL}/register`, {
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
            console.log('Attempting login with:', credentials); // Debug log
            const data = await fetchAPI(`${AUTH_BASE_URL}/login`, {
                method: 'POST',
                body: JSON.stringify(credentials),
            });
            
            // Store the token in localStorage
            if (data.token) {
                // Ensure token is properly formatted
                const token = data.token.trim();
                localStorage.setItem('token', token);
                localStorage.setItem('user', JSON.stringify(data.user));
                console.log('Login successful, token stored'); // Debug log
            }

            return data;
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

            console.log('Sending profile request with token:', token); // Debug log
            return await fetchAPI(`${AUTH_BASE_URL}/profile`, {
                headers: {
                    'Authorization': `Bearer ${token.trim()}`, // Ensure token is trimmed
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
};

export default authService; 