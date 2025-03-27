# RegisterForm Component

## Overview

The `RegisterForm` component is a React component that handles user registration for the Innovation Hub Platform. It provides a comprehensive form for new users to create their accounts with role-specific options.

## Component Structure

```typescript
interface UserRegistrationData {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  role: string;
  dateOfBirth?: string;
}

interface RegisterFormProps {
  onSubmit: (userData: UserRegistrationData) => Promise<void>;
  error?: string;
}
```

## Visual Representation

```
+------------------------------------------+
|           Create Account                 |
|                                          |
|  First Name: [                      ]    |
|                                          |
|  Last Name: [                       ]    |
|                                          |
|  Email: [                           ]    |
|                                          |
|  Password: [                        ]    |
|                                          |
|  Role: [Select Role ▼              ]    |
|                                          |
|  Date of Birth: [                  ]    |
|                                          |
|  [        Create Account Button     ]    |
|                                          |
|  Already have an account? Login          |
+------------------------------------------+
```

## Features

- Comprehensive user registration form
- Role selection (Inventor, Investor, Researcher)
- Form validation
- Loading state handling
- Error message display
- Navigation to login page
- Responsive design

## Props

| Prop | Type | Description |
|------|------|-------------|
| onSubmit | `(userData: UserRegistrationData) => Promise<void>` | Function to handle form submission |
| error | `string` (optional) | Error message to display |

## State Management

```typescript
const [formData, setFormData] = useState<UserRegistrationData>({
  email: '',
  password: '',
  firstName: '',
  lastName: '',
  role: 'inventor',
  dateOfBirth: ''
});
const [isLoading, setIsLoading] = useState(false);
```

## Usage Example

```typescript
import RegisterForm from './components/auth/RegisterForm';

const App = () => {
  const handleRegister = async (userData: UserRegistrationData) => {
    try {
      await authService.register(userData);
      // Handle successful registration
    } catch (error) {
      // Handle error
    }
  };

  return (
    <RegisterForm 
      onSubmit={handleRegister}
      error="Registration failed"
    />
  );
};
```

## Styling

The component uses CSS modules for styling. Key styles include:

```css
.register-form-container {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  background-color: #f5f5f5;
}

.register-form {
  background: white;
  padding: 2rem;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  width: 100%;
  max-width: 500px;
}
```

## Component States

### Normal State
- Empty form fields
- Default role selection
- Enabled submit button
- No error message

### Loading State
- Disabled submit button
- "Creating Account..." text
- Disabled form fields

### Error State
- Red error message box
- Enabled form fields
- Enabled submit button

## Event Handlers

### handleChange
```typescript
const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
  const { name, value } = e.target;
  setFormData(prev => ({
    ...prev,
    [name]: value
  }));
};
```

### handleSubmit
```typescript
const handleSubmit = async (e: React.FormEvent) => {
  e.preventDefault();
  setIsLoading(true);
  try {
    await onSubmit(formData);
    navigate('/login');
  } catch (err) {
    console.error('Registration failed:', err);
  } finally {
    setIsLoading(false);
  }
};
```

## Form Validation

### Required Fields
- First Name
- Last Name
- Email
- Password
- Role

### Validation Rules
- Email format validation
- Password strength requirements
- Date of birth format validation

## Accessibility

- Form labels for all inputs
- Required field validation
- Error message announcements
- Keyboard navigation support
- ARIA attributes
- Role selection dropdown

## Testing

### Unit Tests
```typescript
describe('RegisterForm', () => {
  it('renders correctly', () => {
    render(<RegisterForm onSubmit={jest.fn()} />);
    expect(screen.getByText('Create Account')).toBeInTheDocument();
  });

  it('handles form submission', async () => {
    const onSubmit = jest.fn();
    render(<RegisterForm onSubmit={onSubmit} />);
    
    fireEvent.change(screen.getByLabelText(/first name/i), {
      target: { value: 'John' }
    });
    
    fireEvent.change(screen.getByLabelText(/last name/i), {
      target: { value: 'Doe' }
    });
    
    fireEvent.change(screen.getByLabelText(/email/i), {
      target: { value: 'john@example.com' }
    });
    
    fireEvent.change(screen.getByLabelText(/password/i), {
      target: { value: 'password123' }
    });
    
    fireEvent.click(screen.getByText(/create account/i));
    
    expect(onSubmit).toHaveBeenCalledWith({
      firstName: 'John',
      lastName: 'Doe',
      email: 'john@example.com',
      password: 'password123',
      role: 'inventor',
      dateOfBirth: ''
    });
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
   - Password strength indicator

2. Security
   - HTTPS
   - Password hashing
   - CSRF protection
   - Input sanitization

3. UX
   - Loading indicators
   - Error feedback
   - Form persistence
   - Clear success messages

## Related Components

- LoginForm
- ProtectedRoute
- AuthContext

## Future Improvements

1. Add password strength indicator
2. Implement email verification
3. Add social registration
4. Enhance form validation
5. Add animation effects
6. Add terms and conditions checkbox
7. Implement progressive form validation 