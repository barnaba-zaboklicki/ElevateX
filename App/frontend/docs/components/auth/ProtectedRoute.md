# ProtectedRoute Component

## Overview

The `ProtectedRoute` component is a React component that implements route protection based on authentication status and user roles. It ensures that only authenticated users with appropriate permissions can access specific routes in the application.

## Component Structure

```typescript
interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredRole?: string;
}
```

## Visual Representation

```
+------------------+     +------------------+     +------------------+
|                  |     |                  |     |                  |
|   Unauthorized   |     |    Loading...    |     |   Protected     |
|    Access        |<--->|     Spinner      |<--->|    Content     |
|                  |     |                  |     |                  |
+------------------+     +------------------+     +------------------+
```

## Features

- Authentication check
- Role-based access control
- Loading state handling
- Automatic redirection
- Fallback UI components

## Props

| Prop | Type | Description |
|------|------|-------------|
| children | `React.ReactNode` | The protected content to render |
| requiredRole | `string` (optional) | The role required to access the route |

## Usage Example

```typescript
import ProtectedRoute from './components/auth/ProtectedRoute';

const App = () => {
  return (
    <Routes>
      <Route
        path="/admin"
        element={
          <ProtectedRoute requiredRole="admin">
            <AdminDashboard />
          </ProtectedRoute>
        }
      />
      <Route
        path="/dashboard"
        element={
          <ProtectedRoute>
            <Dashboard />
          </ProtectedRoute>
        }
      />
    </Routes>
  );
};
```

## Component States

### Loading State
```typescript
if (isLoading) {
  return (
    <div className="loading-container">
      <div className="loading-spinner"></div>
      <p>Loading...</p>
    </div>
  );
}
```

### Unauthorized State
```typescript
if (!isAuthenticated) {
  return <Navigate to="/login" state={{ from: location }} replace />;
}
```

### Role Check State
```typescript
if (requiredRole && user?.role !== requiredRole) {
  return <Navigate to="/unauthorized" replace />;
}
```

## Styling

The component uses CSS modules for styling. Key styles include:

```css
.loading-container {
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  background-color: #f5f5f5;
}

.loading-spinner {
  width: 50px;
  height: 50px;
  border: 5px solid #f3f3f3;
  border-top: 5px solid #4a90e2;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin-bottom: 1rem;
}
```

## Authentication Flow

1. Component mounts
2. Checks authentication status
3. Shows loading spinner if checking
4. Redirects to login if not authenticated
5. Checks role if required
6. Redirects to unauthorized if role mismatch
7. Renders protected content if authorized

## Error Handling

- Handles authentication errors
- Manages loading states
- Provides fallback UI
- Logs unauthorized access attempts

## Testing

### Unit Tests
```typescript
describe('ProtectedRoute', () => {
  it('redirects to login when not authenticated', () => {
    render(
      <AuthProvider>
        <ProtectedRoute>
          <div>Protected Content</div>
        </ProtectedRoute>
      </AuthProvider>
    );
    expect(screen.getByText(/loading/i)).toBeInTheDocument();
  });

  it('redirects to unauthorized when role mismatch', () => {
    render(
      <AuthProvider>
        <ProtectedRoute requiredRole="admin">
          <div>Protected Content</div>
        </ProtectedRoute>
      </AuthProvider>
    );
    expect(screen.getByText(/unauthorized/i)).toBeInTheDocument();
  });
});
```

## Dependencies

- React
- React Router
- AuthContext
- CSS Modules

## Best Practices

1. Security
   - Always check authentication
   - Validate roles
   - Handle token expiration
   - Log security events

2. UX
   - Show loading states
   - Clear error messages
   - Smooth transitions
   - Preserve navigation state

3. Performance
   - Minimize re-renders
   - Cache authentication state
   - Optimize redirects
   - Handle edge cases

## Related Components

- LoginForm
- RegisterForm
- AuthContext
- LoadingSpinner

## Future Improvements

1. Add role hierarchy
2. Implement route permissions
3. Add session timeout handling
4. Enhance error messages
5. Add transition animations
6. Implement route caching
7. Add audit logging 