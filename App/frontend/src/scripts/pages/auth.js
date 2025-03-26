import authService from '../../services/auth.js';

// DOM Elements
const loginWrapper = document.querySelector('.login-wrapper');
const registerWrapper = document.querySelector('.register-wrapper');
const formRegisterBtn = document.querySelector('#show-register');
const navbarRegisterBtn = document.querySelector('#navbar-register');
const showLoginBtn = document.querySelector('#show-login');

// Password validation regex patterns
const PASSWORD_PATTERNS = {
    minLength: /.{8,}/,
    uppercase: /[A-Z]/,
    lowercase: /[a-z]/,
    number: /\d/,
    special: /[@$!%*?&]/
};

// Form Toggle Functions
function showRegisterForm() {
    if (loginWrapper && registerWrapper) {
        loginWrapper.style.display = 'none';
        registerWrapper.classList.add('active');
    }
}

function showLoginForm() {
    if (loginWrapper && registerWrapper) {
        registerWrapper.classList.remove('active');
        loginWrapper.style.display = 'flex';
    }
}

// Error Handling Functions
function showError(message, element = null) {
    // Create or get error message element
    let errorElement;
    
    if (element) {
        errorElement = element.parentElement.querySelector('.error-message');
        if (!errorElement) {
            errorElement = document.createElement('div');
            errorElement.className = 'error-message';
            errorElement.style.color = 'red';
            errorElement.style.fontSize = '0.7rem';
            errorElement.style.position = 'absolute';
            errorElement.style.top = '35px';
            errorElement.style.left = '45px';
            element.parentElement.appendChild(errorElement);
        }
        errorElement.textContent = message;
    } else {
        // If no element provided, show as alert
        alert(message);
    }
}

function showSuccess(message) {
    alert(message);
}

function validatePassword(password, passwordInput) {
    const requirementsDiv = passwordInput.parentElement.querySelector('.password-requirements');
    if (!requirementsDiv) return false;

    const requirements = [
        { pattern: PASSWORD_PATTERNS.minLength, text: 'At least 8 characters', met: false },
        { pattern: PASSWORD_PATTERNS.uppercase, text: 'One uppercase letter', met: false },
        { pattern: PASSWORD_PATTERNS.lowercase, text: 'One lowercase letter', met: false },
        { pattern: PASSWORD_PATTERNS.number, text: 'One number', met: false },
        { pattern: PASSWORD_PATTERNS.special, text: 'One special character (@$!%*?&)', met: false }
    ];

    // Check each requirement
    requirements.forEach(req => {
        req.met = req.pattern.test(password);
    });

    // Update the requirements display
    const requirementsList = requirementsDiv.querySelector('ul');
    requirementsList.innerHTML = requirements.map(req => `
        <li style="color: ${req.met ? '#4CAF50' : '#ff4444'}">
            ${req.met ? '✓' : '✗'} ${req.text}
        </li>
    `).join('');

    return requirements.every(req => req.met);
}

// Form Validation
function validateLoginForm(email, password) {
    if (!email || !password) {
        showError('Please fill in all fields');
        return false;
    }
    if (!isValidEmail(email)) {
        showError('Please enter a valid email address');
        return false;
    }
    return true;
}

function validateRegisterForm(formData, form) {
    const { firstName, lastName, email, password, confirmPassword, role, dateOfBirth } = formData;

    if (!firstName || !lastName || !email || !password || !confirmPassword || !role || !dateOfBirth) {
        showError('Please fill in all fields');
        return false;
    }

    if (!isValidEmail(email)) {
        showError('Please enter a valid email address');
        return false;
    }

    const passwordInput = form.querySelector('input[type="password"]');
    if (!validatePassword(password, passwordInput)) {
        return false;
    }

    if (password !== confirmPassword) {
        showError('Passwords do not match');
        return false;
    }

    // Validate date of birth
    const dob = new Date(dateOfBirth);
    const today = new Date();
    const age = today.getFullYear() - dob.getFullYear();
    if (age < 18) {
        showError('You must be at least 18 years old to register');
        return false;
    }

    return true;
}

// Utility Functions
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    // Initialize forms
    if (loginWrapper && registerWrapper) {
        loginWrapper.style.display = 'flex';
        registerWrapper.classList.remove('active');
    }

    // Add password requirements info
    const passwordInput = document.querySelector('.register-wrapper input[type="password"]');
    if (passwordInput) {
        const requirementsDiv = document.createElement('div');
        requirementsDiv.className = 'password-requirements';
        requirementsDiv.style.display = 'none';
        requirementsDiv.style.position = 'absolute';
        requirementsDiv.style.backgroundColor = 'rgba(0, 0, 0, 0.9)';
        requirementsDiv.style.padding = '10px';
        requirementsDiv.style.borderRadius = '5px';
        requirementsDiv.style.zIndex = '1000';
        requirementsDiv.style.marginTop = '5px';
        requirementsDiv.style.width = '250px';
        requirementsDiv.innerHTML = `
            <small style="color: #fff; font-size: 0.7rem;">
                Password requirements:
                <ul style="margin: 5px 0; padding-left: 20px;">
                    <li>At least 8 characters</li>
                    <li>One uppercase letter</li>
                    <li>One lowercase letter</li>
                    <li>One number</li>
                    <li>One special character (@$!%*?&)</li>
                </ul>
            </small>
        `;
        passwordInput.parentElement.appendChild(requirementsDiv);

        // Show requirements only when password field is focused
        const allInputs = document.querySelectorAll('.register-wrapper input, .register-wrapper select');
        allInputs.forEach(input => {
            input.addEventListener('focus', () => {
                if (input === passwordInput) {
                    requirementsDiv.style.display = 'block';
                    // Initial validation if there's a value
                    if (passwordInput.value) {
                        validatePassword(passwordInput.value, passwordInput);
                    }
                } else {
                    requirementsDiv.style.display = 'none';
                }
            });
        });

        // Real-time password validation
        passwordInput.addEventListener('input', (e) => {
            requirementsDiv.style.display = 'block';
            validatePassword(e.target.value, e.target);
        });
    }

    // Form Toggle Event Listeners
    if (formRegisterBtn) {
        formRegisterBtn.addEventListener('click', (e) => {
            e.preventDefault();
            showRegisterForm();
        });
    }

    if (navbarRegisterBtn) {
        navbarRegisterBtn.addEventListener('click', (e) => {
            e.preventDefault();
            showRegisterForm();
        });
    }

    if (showLoginBtn) {
        showLoginBtn.addEventListener('click', (e) => {
            e.preventDefault();
            showLoginForm();
        });
    }

    // Login Form Submission
    const loginForm = document.querySelector('.login-wrapper form');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const email = loginForm.querySelector('input[type="email"]').value;
            const password = loginForm.querySelector('input[type="password"]').value;

            if (!validateLoginForm(email, password)) {
                return;
            }

            try {
                const response = await authService.login({ email, password });
                showSuccess('Login successful!');
                
                // Redirect to unified dashboard
                window.location.href = '/src/pages/dashboard/dashboard.html';
            } catch (error) {
                // Check for rate limit error
                if (error.message && error.message.includes('Too many login attempts')) {
                    showError('Account temporarily locked. Please try again later.');
                } else {
                    showError(error.message);
                }
            }
        });
    }

    // Registration Form Submission
    const registerForm = document.querySelector('.register-wrapper form');
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = {
                firstName: registerForm.querySelector('.input-box:nth-of-type(1) input').value,
                lastName: registerForm.querySelector('.input-box:nth-of-type(2) input').value,
                email: registerForm.querySelector('.input-box:nth-of-type(3) input').value,
                dateOfBirth: registerForm.querySelector('.input-box:nth-of-type(4) input').value,
                password: registerForm.querySelector('.input-box:nth-of-type(5) input').value,
                confirmPassword: registerForm.querySelector('.input-box:nth-of-type(6) input').value,
                role: registerForm.querySelector('.role-select select').value
            };

            if (!validateRegisterForm(formData, registerForm)) {
                return;
            }

            try {
                await authService.register(formData);
                showSuccess('Registration successful! Please login.');
                showLoginForm();
                registerForm.reset();
            } catch (error) {
                showError(error.message);
            }
        });
    }
}); 