# LoginForm Component

## Overview

The `LoginForm` component is a React component that handles user authentication through a form interface. It provides a clean and user-friendly way for users to log in to the Innovation Hub Platform.

## Component Structure

```typescript
interface LoginFormProps {
  onSubmit: (email: string, password: string) => Promise<void>;
  error?: string;
}
```

## Visual Representation

```
+------------------------------------------+
|              Welcome Back                |
|                                          |
|  Email: [                           ]    |
|                                          |
|  Password: [                        ]    |
|                                          |
|  [           Login Button           ]    |
|                                          |
|  Don't have an account? Register         |
+------------------------------------------+
```

## Features

- Email and password input fields
- Form validation
- Loading state handling
- Error message display
- Navigation to registration page
- Responsive design

## Props

| Prop | Type | Description |
|------|------|-------------|
| onSubmit | `(email: string, password: string) => Promise<void>` | Function to handle form submission |
| error | `string` (optional) | Error message to display |

## State Management

```typescript
const [email, setEmail] = useState('');
const [password, setPassword] = useState('');
const [isLoading, setIsLoading] = useState(false);
```

## Usage Example

```typescript
import LoginForm from './components/auth/LoginForm';

const App = () => {
  const handleLogin = async (email: string, password: string) => {
    try {
      await authService.login({ email, password });
      // Handle successful login
    } catch (error) {
      // Handle error
    }
  };

  return (
    <LoginForm 
      onSubmit={handleLogin}
      error="Invalid credentials"
    />
  );
};
```

## Styling

The component uses CSS modules for styling. Key styles include:

```css
.login-form-container {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  background-color: #f5f5f5;
}

.login-form {
  background: white;
  padding: 2rem;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  width: 100%;
  max-width: 400px;
}
```

## Component States

### Normal State
- Empty form fields
- Enabled submit button
- No error message

### Loading State
- Disabled submit button
- "Logging in..." text
- Disabled form fields

### Error State
- Red error message box
- Enabled form fields
- Enabled submit button

## Event Handlers

### handleSubmit
```typescript
const handleSubmit = async (e: React.FormEvent) => {
  e.preventDefault();
  setIsLoading(true);
  try {
    await onSubmit(email, password);
    navigate('/dashboard');
  } catch (err) {
    console.error('Login failed:', err);
  } finally {
    setIsLoading(false);
  }
};
```

## Accessibility

- Form labels for all inputs
- Required field validation
- Error message announcements
- Keyboard navigation support
- ARIA attributes

## Testing

### Unit Tests
```typescript
describe('LoginForm', () => {
  it('renders correctly', () => {
    render(<LoginForm onSubmit={jest.fn()} />);
    expect(screen.getByText('Welcome Back')).toBeInTheDocument();
  });

  it('handles form submission', async () => {
    const onSubmit = jest.fn();
    render(<LoginForm onSubmit={onSubmit} />);
    
    fireEvent.change(screen.getByLabelText(/email/i), {
      target: { value: 'test@example.com' }
    });
    
    fireEvent.change(screen.getByLabelText(/password/i), {
      target: { value: 'password123' }
    });
    
    fireEvent.click(screen.getByText(/login/i));
    
    expect(onSubmit).toHaveBeenCalledWith('test@example.com', 'password123');
  });
});
```

## Dependencies

- React
- React Router
- TypeScript
- CSS Modules

## Best Practices

1. Form Validation
   - Client-side validation
   - Server-side validation
   - Clear error messages

2. Security
   - HTTPS
   - Password hashing
   - CSRF protection

3. UX
   - Loading indicators
   - Error feedback
   - Form persistence

## Related Components

- RegisterForm
- ProtectedRoute
- AuthContext

## Future Improvements

1. Add "Remember Me" functionality
2. Implement social login
3. Add password recovery
4. Enhance form validation
5. Add animation effects 