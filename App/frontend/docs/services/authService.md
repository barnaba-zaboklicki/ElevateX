# Authentication Service

## Overview

The `AuthService` is a TypeScript service that handles all authentication-related API calls and local storage management. It provides a clean interface for authentication operations and manages the persistence of authentication data.

## Service Structure

```typescript
interface UserRegistrationData {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  role: string;
  dateOfBirth?: string;
}

interface LoginCredentials {
  email: string;
  password: string;
}

interface AuthResponse {
  token: string;
  user: {
    id: number;
    email: string;
    firstName: string;
    lastName: string;
    role: string;
    dateOfBirth?: string;
  };
}
```

## Visual Representation

```
+------------------+     +------------------+     +------------------+
|                  |     |                  |     |                  |
|   AuthContext    |<--->|   AuthService    |<--->|   Backend API   |
|                  |     |                  |     |                  |
+------------------+     +------------------+     +------------------+
         ^                        ^                        ^
         |                        |                        |
         v                        v                        v
+------------------+     +------------------+     +------------------+
|                  |     |                  |     |                  |
|   Local Storage  |     |   Token Management|   |   HTTP Requests  |
|                  |     |                  |     |                  |
+------------------+     +------------------+     +------------------+
```

## Features

- User authentication
- User registration
- Token management
- Local storage persistence
- Profile management
- Role-based access control

## API Endpoints

```typescript
const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

const endpoints = {
  login: `${API_URL}/auth/login`,
  register: `${API_URL}/auth/register`,
  profile: `${API_URL}/auth/profile`
};
```

## Methods

### Login
```typescript
async login(credentials: LoginCredentials): Promise<AuthResponse> {
  try {
    const response = await axios.post(endpoints.login, credentials);
    if (response.data.token) {
      localStorage.setItem('token', response.data.token);
      localStorage.setItem('user', JSON.stringify(response.data.user));
    }
    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      throw new Error(error.response?.data?.message || 'Login failed');
    }
    throw error;
  }
}
```

### Register
```typescript
async register(userData: UserRegistrationData): Promise<void> {
  try {
    await axios.post(endpoints.register, userData);
  } catch (error) {
    if (axios.isAxiosError(error)) {
      throw new Error(error.response?.data?.message || 'Registration failed');
    }
    throw error;
  }
}
```

### Get Profile
```typescript
async getProfile(): Promise<AuthResponse['user']> {
  try {
    const token = this.getToken();
    const response = await axios.get(endpoints.profile, {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      throw new Error(error.response?.data?.message || 'Failed to get profile');
    }
    throw error;
  }
}
```

## Local Storage Management

### Token Management
```typescript
getToken(): string | null {
  return localStorage.getItem('token');
}

setToken(token: string): void {
  localStorage.setItem('token', token);
}

removeToken(): void {
  localStorage.removeItem('token');
}
```

### User Data Management
```typescript
getCurrentUser(): AuthResponse['user'] | null {
  const userStr = localStorage.getItem('user');
  return userStr ? JSON.parse(userStr) : null;
}

setCurrentUser(user: AuthResponse['user']): void {
  localStorage.setItem('user', JSON.stringify(user));
}

removeCurrentUser(): void {
  localStorage.removeItem('user');
}
```

## Error Handling

### API Error Handling
```typescript
private handleApiError(error: unknown): never {
  if (axios.isAxiosError(error)) {
    const message = error.response?.data?.message || 'An error occurred';
    throw new Error(message);
  }
  throw error;
}
```

### Validation
```typescript
private validateCredentials(credentials: LoginCredentials): void {
  if (!credentials.email || !credentials.password) {
    throw new Error('Email and password are required');
  }
}
```

## Testing

### Unit Tests
```typescript
describe('AuthService', () => {
  it('handles successful login', async () => {
    const mockResponse = {
      token: 'test-token',
      user: {
        id: 1,
        email: 'test@example.com',
        firstName: 'Test',
        lastName: 'User',
        role: 'user'
      }
    };

    axios.post.mockResolvedValueOnce({ data: mockResponse });

    const result = await authService.login({
      email: 'test@example.com',
      password: 'password'
    });

    expect(result).toEqual(mockResponse);
    expect(localStorage.getItem('token')).toBe('test-token');
  });

  it('handles login error', async () => {
    axios.post.mockRejectedValueOnce(new Error('Invalid credentials'));

    await expect(authService.login({
      email: 'test@example.com',
      password: 'wrong'
    })).rejects.toThrow('Invalid credentials');
  });
});
```

## Dependencies

- Axios
- Local Storage API
- TypeScript

## Best Practices

1. API Integration
   - Consistent error handling
   - Request/response typing
   - Token management
   - Request interceptors

2. Security
   - Secure storage
   - Token validation
   - Error handling
   - Input validation

3. Performance
   - Response caching
   - Request optimization
   - Error recovery
   - State management

## Related Components

- AuthContext
- LoginForm
- RegisterForm
- ProtectedRoute

## Future Improvements

1. Add refresh token mechanism
2. Implement request retry
3. Add request caching
4. Enhance error handling
5. Add request queuing
6. Implement offline support
7. Add request analytics 