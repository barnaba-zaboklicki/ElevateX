// Role-specific menu items and configurations
const roleConfigs = {
    admin: {
        title: 'Admin Dashboard',
        menuItems: [
            {
                id: 'users',
                icon: '<svg xmlns="http://www.w3.org/2000/svg" height="24" viewBox="0 -960 960 960" width="24"><path d="M400-480q-66 0-113-47t-47-113q0-66 47-113t113-47q66 0 113 47t47 113q0 66-47 113t-113 47ZM80-160v-112q0-33 17-62t47-44q51-26 115-44t141-18q77 0 141 18t115 44q30 15 47 44t17 62v112H80Zm80-80h480v-32q0-11-5.5-20T620-306q-36-18-92.5-36T400-360q-71 0-127.5 18T180-306q-9 5-14.5 14t-5.5 20v32Zm240-320q33 0 56.5-23.5T480-640q0-33-23.5-56.5T400-720q-33 0-56.5 23.5T320-640q0 33 23.5 56.5T400-560Zm0-80Zm0 400Z"/></svg>',
                text: 'Users',
                href: '#'
            },
            {
                id: 'security',
                icon: '<svg xmlns="http://www.w3.org/2000/svg" height="24" viewBox="0 -960 960 960" width="24"><path d="M480-80q-139-35-229.5-159.5T160-516v-244l320-120 320 120v244q0 152-90.5 276.5T480-80Zm0-84q97-30 162-118.5T718-480H480v-315l-240 90v207q0 7 2 18h238v316Z"/></svg>',
                text: 'Security Logs',
                href: '#'
            }
        ]
    },
    investor: {
        title: 'Investor Dashboard',
        menuItems: [
            {
                id: 'projects',
                icon: '<svg xmlns="http://www.w3.org/2000/svg" height="24" viewBox="0 -960 960 960" width="24"><path d="m234-480-12-60q-12-5-22.5-10.5T178-564l-58 18-40-68 46-40q-2-13-2-26t2-26l-46-40 40-68 58 18q11-8 21.5-13.5T222-820l12-60h80l12 60q12 5 22.5 10.5T370-796l58-18 40 68-46 40q2 13 2 26t-2 26l46 40-40 68-58-18q-11 8-21.5 13.5T326-540l-12 60h-80Z"/></svg>',
                text: 'My Projects',
                href: '#'
            },
            {
                id: 'requests',
                icon: '<svg xmlns="http://www.w3.org/2000/svg" height="24" viewBox="0 -960 960 960" width="24"><path d="M120-120v-80l80-80v160h-80Zm160 0v-240l80-80v320h-80Z"/></svg>',
                text: 'Investment Requests',
                href: '#'
            }
        ]
    },
    inventor: {
        title: 'Inventor Dashboard',
        menuItems: [
            {
                id: 'addProject',
                icon: '<svg xmlns="http://www.w3.org/2000/svg" height="24" viewBox="0 -960 960 960" width="24"><path d="M440-440H200v-80h240v-240h80v240h240v80H520v240h-80v-240Z"/></svg>',
                text: 'Add New Project',
                href: '#'
            },
            {
                id: 'myInventions',
                icon: '<svg xmlns="http://www.w3.org/2000/svg" height="24" viewBox="0 -960 960 960" width="24"><path d="M440-280h80v-160h160v-80H520v-160h-80v160H280v80h160v160Z"/></svg>',
                text: 'My Inventions',
                href: '#'
            },
            {
                id: 'patents',
                icon: '<svg xmlns="http://www.w3.org/2000/svg" height="24" viewBox="0 -960 960 960" width="24"><path d="M480-80q-83 0-156-31.5T197-197q-54-54-85.5-127T80-480q0-83 31.5-156T197-763q54-54 127-85.5T480-880q83 0 156 31.5T763-763q54 54 85.5 127T880-480q0 83-31.5 156T763-197q-54 54-127 85.5T480-80Z"/></svg>',
                text: 'Patents',
                href: '#'
            }
        ]
    },
    researcher: {
        title: 'Researcher Dashboard',
        menuItems: [
            {
                id: 'research',
                icon: '<svg xmlns="http://www.w3.org/2000/svg" height="24" viewBox="0 -960 960 960" width="24"><path d="M440-280h80v-160h160v-80H520v-160h-80v160H280v80h160v160Z"/></svg>',
                text: 'Research Projects',
                href: '#'
            },
            {
                id: 'publications',
                icon: '<svg xmlns="http://www.w3.org/2000/svg" height="24" viewBox="0 -960 960 960" width="24"><path d="M160-160q-33 0-56.5-23.5T80-240v-480q0-33 23.5-56.5T160-800h640q33 0 56.5 23.5T880-720v480q0 33-23.5 56.5T800-160H160Z"/></svg>',
                text: 'Publications',
                href: '#'
            }
        ]
    }
};

// Function to get user role from localStorage
function getUserRole() {
    const user = JSON.parse(localStorage.getItem('user'));
    return user ? user.role : null;
}

// Function to create menu item HTML
function createMenuItem(item) {
    return `
        <li>
            <a href="${item.href}" data-menu="${item.id}">
                ${item.icon}
                <span>${item.text}</span>
            </a>
        </li>
    `;
}

// Function to load role-specific menu items
function loadRoleSpecificMenu(role) {
    const config = roleConfigs[role];
    if (!config) return;

    // Set page title
    document.title = config.title;

    // Add role-specific menu items
    const menuContainer = document.getElementById('role-specific-menu');
    const menuHTML = config.menuItems.map(createMenuItem).join('');
    menuContainer.innerHTML = menuHTML;
}

// Function to load role-specific content
function loadDashboardContent(role) {
    const contentDiv = document.getElementById('dashboard-content');
    const user = JSON.parse(localStorage.getItem('user'));
    const firstName = user ? user.first_name : '';
    
    let content = `
        <div class="welcome-section">
            <h1>Welcome, ${firstName}!</h1>
            <h2>${roleConfigs[role].title}</h2>
        </div>
        <div class="dashboard-sections">`;

    // Add common dashboard content
    content += `
            <div class="container">
                <h2>Hello World</h2>
                <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit...</p>
            </div>
            <div class="container">
                <h2>What is Lorem Ipsum?</h2>
                <p>Lorem ipsum dolor sit amet consectetur adipisicing elit...</p>
            </div>
            <div class="container">
                <h2>Why do we use it?</h2>
                <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit...</p>
            </div>
        </div>
    `;
    
    contentDiv.innerHTML = content;
}

// Function to handle logout
function handleLogout() {
    // Clear user data from localStorage
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    
    // Redirect to login page
    window.location.href = '../landing/index.html';
}

// Function to create idea submission form
function createIdeaSubmissionForm() {
    return `
        <form id="ideaSubmissionForm" class="idea-form">
            <div class="form-group">
                <label for="title">Title</label>
                <input type="text" id="title" name="title" required>
            </div>
            
            <div class="form-group">
                <label for="description">Description</label>
                <textarea id="description" name="description" rows="4" required></textarea>
            </div>
            
            <div class="form-group">
                <label for="technical_details">Technical Details</label>
                <textarea id="technical_details" name="technical_details" rows="4" required></textarea>
            </div>
            
            <div class="form-group">
                <label for="patent_status">Patent Status</label>
                <select id="patent_status" name="patent_status" required>
                    <option value="">Select status</option>
                    <option value="not_filed">Not Filed</option>
                    <option value="in_progress">In Progress</option>
                    <option value="granted">Granted</option>
                    <option value="rejected">Rejected</option>
                </select>
            </div>
            
            <div class="form-group">
                <label for="funding_status">Funding Status</label>
                <select id="funding_status" name="funding_status" required>
                    <option value="">Select status</option>
                    <option value="not_requested">Not Requested</option>
                    <option value="requested">Requested</option>
                    <option value="approved">Approved</option>
                    <option value="rejected">Rejected</option>
                </select>
            </div>
            
            <div class="form-group">
                <label for="attachments">Attachments</label>
                <input type="file" id="attachments" name="attachments" multiple
                    accept=".pdf,.doc,.docx,.ppt,.pptx,.jpg,.jpeg,.png">
                <small>Max file size: 10MB each (50MB total)</small>
                <div id="selectedFiles" class="selected-files"></div>
            </div>
            
            <button type="submit" class="submit-button">
                Submit Invention
            </button>
        </form>
    `;
}

// Function to handle idea submission
async function handleIdeaSubmission(e) {
    e.preventDefault();
    
    const form = e.target;
    const formData = new FormData(form);
    const token = localStorage.getItem('token');
    
    if (!token) {
        alert('You are not logged in. Please log in again.');
        window.location.href = '../landing/index.html';
        return;
    }
    
    // Validate required fields
    const title = formData.get('title')?.trim();
    const description = formData.get('description')?.trim();
    const technical_details = formData.get('technical_details')?.trim();
    const patent_status = formData.get('patent_status');
    const funding_status = formData.get('funding_status');
    
    if (!title || !description || !technical_details || !patent_status || !funding_status) {
        alert('Please fill in all required fields');
        return;
    }
    
    try {
        // Create a new FormData object for the request
        const requestData = new FormData();
        
        // Add text fields
        requestData.append('title', title);
        requestData.append('description', description);
        requestData.append('technical_details', technical_details);
        requestData.append('patent_status', patent_status);
        requestData.append('funding_status', funding_status);
        
        // Add files if they exist
        const files = formData.getAll('attachments');
        files.forEach(file => {
            requestData.append('attachments', file);
        });
        
        // Debug logging
        console.log('Form data entries:');
        for (let [key, value] of requestData.entries()) {
            console.log(`${key}:`, value);
        }
        
        // Debug log the token
        console.log('Using token:', token);
        
        const response = await fetch('https://127.0.0.1:5000/api/inventions', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Accept': 'application/json'
            },
            credentials: 'include',
            body: requestData
        });

        if (!response.ok) {
            if (response.status === 401) {
                // Token expired or invalid
                const errorData = await response.json();
                console.error('Authentication error:', errorData);
                
                // Clear user data and redirect to login
                localStorage.removeItem('token');
                localStorage.removeItem('user');
                alert('Your session has expired. Please log in again.');
                window.location.href = '../landing/index.html';
                return;
            }
            const errorData = await response.json();
            console.error('Server error response:', errorData);
            throw new Error(errorData.message || errorData.msg || 'Failed to submit idea');
        }

        const result = await response.json();
        alert('Idea submitted successfully!');
        form.reset();
        
        // Clear selected files display
        const selectedFilesDiv = document.getElementById('selectedFiles');
        if (selectedFilesDiv) {
            selectedFilesDiv.innerHTML = '';
        }
    } catch (error) {
        console.error('Error submitting idea:', error);
        alert('Failed to submit idea. Please try again.');
    }
}

// Function to check token expiration
function checkTokenExpiration() {
    const token = localStorage.getItem('token');
    if (!token) return false;
    
    try {
        // Decode the JWT token (it's base64 encoded)
        const payload = JSON.parse(atob(token.split('.')[1]));
        const expiration = payload.exp * 1000; // Convert to milliseconds
        const now = Date.now();
        
        // If token expires in less than 5 minutes, consider it expired
        return now < expiration - 300000;
    } catch (error) {
        console.error('Error checking token expiration:', error);
        return false;
    }
}

// Function to handle menu item click
function handleMenuClick(menuId) {
    const contentDiv = document.getElementById('dashboard-content');
    const user = JSON.parse(localStorage.getItem('user'));
    
    // Remove active class from all menu items
    document.querySelectorAll('#sidebar li').forEach(li => {
        li.classList.remove('active');
    });
    
    // Add active class to clicked menu item's parent li
    const activeLink = document.querySelector(`#sidebar a[data-menu="${menuId}"]`);
    if (activeLink) {
        activeLink.parentElement.classList.add('active');
    }

    // Handle different menu items
    if (menuId === 'home') {
        // Load default dashboard content
        loadDashboardContent(user.role);
    } else if (user.role === 'inventor') {
        switch (menuId) {
            case 'addProject':
                contentDiv.innerHTML = `
                    <div class="welcome-section">
                        <h1>Welcome, ${user.first_name}!</h1>
                        <h2>${roleConfigs[user.role].title}</h2>
                    </div>
                    <div class="dashboard-sections">
                        <div class="container">
                            <h2>Submit New Invention</h2>
                            ${createIdeaSubmissionForm()}
                        </div>
                    </div>
                `;
                
                // Add event listener for the form
                const form = document.getElementById('ideaSubmissionForm');
                if (form) {
                    form.addEventListener('submit', handleIdeaSubmission);
                }
                break;
            case 'myInventions':
                contentDiv.innerHTML = `
                    <div class="welcome-section">
                        <h1>Welcome, ${user.first_name}!</h1>
                        <h2>${roleConfigs[user.role].title}</h2>
                    </div>
                    <div class="dashboard-sections">
                        <div class="container">
                            <h2>My Inventions</h2>
                            <p>Your inventions will be displayed here...</p>
                        </div>
                    </div>
                `;
                break;
            case 'patents':
                contentDiv.innerHTML = `
                    <div class="welcome-section">
                        <h1>Welcome, ${user.first_name}!</h1>
                        <h2>${roleConfigs[user.role].title}</h2>
                    </div>
                    <div class="dashboard-sections">
                        <div class="container">
                            <h2>Patents</h2>
                            <p>Your patents will be displayed here...</p>
                        </div>
                    </div>
                `;
                break;
        }
    } else if (user.role === 'investor') {
        switch (menuId) {
            case 'projects':
                contentDiv.innerHTML = `
                    <div class="welcome-section">
                        <h1>Welcome, ${user.first_name}!</h1>
                        <h2>${roleConfigs[user.role].title}</h2>
                    </div>
                    <div class="dashboard-sections">
                        <div class="container">
                            <h2>My Projects</h2>
                            <p>Your investment projects will be displayed here...</p>
                        </div>
                    </div>
                `;
                break;
            case 'requests':
                contentDiv.innerHTML = `
                    <div class="welcome-section">
                        <h1>Welcome, ${user.first_name}!</h1>
                        <h2>${roleConfigs[user.role].title}</h2>
                    </div>
                    <div class="dashboard-sections">
                        <div class="container">
                            <h2>Investment Requests</h2>
                            <p>Investment requests will be displayed here...</p>
                        </div>
                    </div>
                `;
                break;
        }
    } else if (user.role === 'admin') {
        switch (menuId) {
            case 'users':
                contentDiv.innerHTML = `
                    <div class="welcome-section">
                        <h1>Welcome, ${user.first_name}!</h1>
                        <h2>${roleConfigs[user.role].title}</h2>
                    </div>
                    <div class="dashboard-sections">
                        <div class="container">
                            <h2>Users Management</h2>
                            <p>User management interface will be displayed here...</p>
                        </div>
                    </div>
                `;
                break;
            case 'security':
                contentDiv.innerHTML = `
                    <div class="welcome-section">
                        <h1>Welcome, ${user.first_name}!</h1>
                        <h2>${roleConfigs[user.role].title}</h2>
                    </div>
                    <div class="dashboard-sections">
                        <div class="container">
                            <h2>Security Logs</h2>
                            <p>Security logs will be displayed here...</p>
                        </div>
                    </div>
                `;
                break;
        }
    } else if (user.role === 'researcher') {
        switch (menuId) {
            case 'research':
                contentDiv.innerHTML = `
                    <div class="welcome-section">
                        <h1>Welcome, ${user.first_name}!</h1>
                        <h2>${roleConfigs[user.role].title}</h2>
                    </div>
                    <div class="dashboard-sections">
                        <div class="container">
                            <h2>Research Projects</h2>
                            <p>Your research projects will be displayed here...</p>
                        </div>
                    </div>
                `;
                break;
            case 'publications':
                contentDiv.innerHTML = `
                    <div class="welcome-section">
                        <h1>Welcome, ${user.first_name}!</h1>
                        <h2>${roleConfigs[user.role].title}</h2>
                    </div>
                    <div class="dashboard-sections">
                        <div class="container">
                            <h2>Publications</h2>
                            <p>Your publications will be displayed here...</p>
                        </div>
                    </div>
                `;
                break;
        }
    }
}

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    // Check if user is logged in and token is valid
    const token = localStorage.getItem('token');
    if (!token || !checkTokenExpiration()) {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        window.location.href = '../landing/index.html';
        return;
    }

    // Get user role and load appropriate content
    const user = JSON.parse(localStorage.getItem('user'));
    if (user) {
        loadRoleSpecificMenu(user.role);
        loadDashboardContent(user.role);
        
        // Set initial active menu item (first item)
        const firstMenuItem = document.querySelector('#sidebar a[data-menu]');
        if (firstMenuItem) {
            firstMenuItem.parentElement.classList.add('active');
        }
    }

    // Add event listeners for menu items
    document.querySelectorAll('#sidebar a[data-menu]').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const menuId = e.currentTarget.getAttribute('data-menu');
            handleMenuClick(menuId);
        });
    });

    // Add event listener for logout button
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', handleLogout);
    }
}); 