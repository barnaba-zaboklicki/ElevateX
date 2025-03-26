# Authentication JavaScript Documentation

## Overview
The `auth.js` file manages user authentication functionality, including login and registration forms, form validation, and API integration.

## Dependencies
- Font Awesome for icons
- Custom API endpoints for authentication

## Key Components

### API Configuration
```javascript
const API_URL = 'http://localhost:3000/api';
```

### DOM Elements
```javascript
const loginForm = document.querySelector('.login-wrapper form');
const registerForm = document.querySelector('.register-wrapper form');
const loginWrapper = document.querySelector('.login-wrapper');
const registerWrapper = document.querySelector('.register-wrapper');
const showRegisterBtn = document.getElementById('show-register');
const showLoginBtn = document.getElementById('show-login');
const navbarRegisterBtn = document.getElementById('navbar-register');
```

## Functions

### Form Toggle Functions

#### `showRegisterForm()`
Displays the registration form and hides the login form.

**Functionality:**
- Hides login wrapper
- Shows registration wrapper with active class

#### `showLoginForm()`
Displays the login form and hides the registration form.

**Functionality:**
- Removes active class from registration wrapper
- Shows login wrapper

### Error Handling

#### `showError(message, type)`
Displays error or success messages to the user.

**Parameters:**
- `message` (string): The message to display
- `type` (string): The type of message ('error' or 'success')

**Functionality:**
- Creates error message element
- Removes existing error messages
- Displays new message
- Auto-removes after 3 seconds

### Form Validation

#### `validateRegistration(formData)`
Validates registration form data.

**Parameters:**
- `formData` (object): The form data to validate

**Returns:**
- `boolean`: Whether the form data is valid

**Validation Rules:**
- Password matching
- Required fields
- Email format

### API Calls

#### `handleLogin(credentials)`
Handles user login API call.

**Parameters:**
- `credentials` (object): User login credentials
  ```javascript
  {
    email: string,
    password: string
  }
  ```

**Functionality:**
- Makes API call to login endpoint
- Handles response
- Stores authentication token
- Shows success/error messages
- Redirects on success

#### `handleRegistration(userData)`
Handles user registration API call.

**Parameters:**
- `userData` (object): User registration data
  ```javascript
  {
    firstName: string,
    lastName: string,
    email: string,
    password: string,
    confirmPassword: string,
    role: string
  }
  ```

**Functionality:**
- Makes API call to registration endpoint
- Handles response
- Shows success/error messages
- Switches to login form on success

## Event Listeners

### Form Submission
```javascript
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(loginForm);
    const credentials = {
        email: formData.get('email'),
        password: formData.get('password'),
    };
    await handleLogin(credentials);
});

registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(registerForm);
    const userData = {
        firstName: formData.get('firstName'),
        lastName: formData.get('lastName'),
        email: formData.get('email'),
        password: formData.get('password'),
        confirmPassword: formData.get('confirmPassword'),
        role: formData.get('role'),
    };

    if (validateRegistration(userData)) {
        await handleRegistration(userData);
    }
});
```

### Form Toggle
```javascript
showRegisterBtn.addEventListener('click', (e) => {
    e.preventDefault();
    showRegisterForm();
});

showLoginBtn.addEventListener('click', (e) => {
    e.preventDefault();
    showLoginForm();
});

navbarRegisterBtn.addEventListener('click', (e) => {
    e.preventDefault();
    showRegisterForm();
});
```

## API Integration

### Endpoints
- Login: `POST ${API_URL}/auth/login`
- Registration: `POST ${API_URL}/auth/register`

### Authentication
- Uses JWT tokens stored in localStorage
- Token format: Bearer token

## Usage
The script is automatically initialized when the page loads. It requires the following HTML structure:
- Login form with class `.login-wrapper`
- Registration form with class `.register-wrapper`
- Form toggle buttons with IDs `show-register` and `show-login`
- Navbar register button with ID `navbar-register`

## Browser Support
- Modern browsers (Chrome, Firefox, Safari, Edge)
- IE11 and above

## Notes
- Form validation is performed both client-side and server-side
- Error messages are automatically removed after 3 seconds
- Success messages trigger appropriate UI updates
- API calls include proper error handling
- Responsive design is supported 