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
                id: 'availableProjects',
                icon: '<svg xmlns="http://www.w3.org/2000/svg" height="24" viewBox="0 -960 960 960" width="24"><path d="M160-160q-33 0-56.5-23.5T80-240v-480q0-33 23.5-56.5T160-800h640q33 0 56.5 23.5T880-720v480q0 33-23.5 56.5T800-160H160Zm0-80h640v-480H160v480Zm0 0v-480 480Z"/></svg>',
                text: 'Available Projects',
                href: '#'
            },
            {
                id: 'myInvestments',
                icon: '<svg xmlns="http://www.w3.org/2000/svg" height="24" viewBox="0 -960 960 960" width="24"><path d="M440-280h80v-160h160v-80H520v-160h-80v160H280v80h160v160Z"/></svg>',
                text: 'My Investments',
                href: '#'
            },
            {
                id: 'investmentHistory',
                icon: '<svg xmlns="http://www.w3.org/2000/svg" height="24" viewBox="0 -960 960 960" width="24"><path d="M480-80q-83 0-156-31.5T197-197q-54-54-85.5-127T80-480q0-83 31.5-156T197-763q54-54 127-85.5T480-880q83 0 156 31.5T763-763q54 54 85.5 127T880-480q0 83-31.5 156T763-197q-54 54-127 85.5T480-80Zm0-80q134 0 227-93t93-227q0-134-93-227t-227-93q-134 0-227 93t-93 227q0 134 93 227t227 93Zm0-320Z"/></svg>',
                text: 'Investment History',
                href: '#'
            },
            {
                id: 'analytics',
                icon: '<svg xmlns="http://www.w3.org/2000/svg" height="24" viewBox="0 -960 960 960" width="24"><path d="M160-160v-640h160v640H160Zm240 0v-400h160v400H400Zm240 0v-240h160v240H640Z"/></svg>',
                text: 'Investment Analytics',
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
            body: requestData,
            mode: 'cors',
            rejectUnauthorized: false
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

// Function to fetch available projects
async function fetchAvailableProjects() {
    const token = localStorage.getItem('token');
    if (!token) {
        console.error('No authentication token found');
        throw new Error('No authentication token found');
    }

    try {
        console.log('Fetching available projects...');
        const response = await fetch('https://127.0.0.1:5000/api/inventions/available', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Accept': 'application/json'
            },
            credentials: 'include',
            mode: 'cors',
            rejectUnauthorized: false
        });

        console.log('Response status:', response.status);
        console.log('Response headers:', Object.fromEntries(response.headers.entries()));

        if (!response.ok) {
            if (response.status === 401) {
                console.error('Authentication failed - redirecting to login');
                localStorage.removeItem('token');
                localStorage.removeItem('user');
                window.location.href = '../landing/index.html';
                return;
            }
            const errorData = await response.json();
            console.error('Server error:', errorData);
            throw new Error(errorData.message || 'Failed to fetch projects');
        }

        const data = await response.json();
        console.log('Received projects:', data);
        return data.projects;
    } catch (error) {
        console.error('Error fetching projects:', error);
        throw error;
    }
}

// Function to create project card HTML
function createProjectCard(project) {
    return `
        <div class="project-card" data-project-id="${project.id}">
            <h3>${project.title}</h3>
            <p>${project.description}</p>
            <div class="project-meta">
                <span class="patent-status">Patent: ${project.patent_status}</span>
                <span class="funding-status">Funding: ${project.funding_status}</span>
                <span class="date">Posted: ${new Date(project.created_at).toLocaleDateString()}</span>
            </div>
            <button class="view-details-btn">View Details</button>
        </div>
    `;
}

// Function to handle invention submission
async function handleInventionSubmission(inventionId) {
    const token = localStorage.getItem('token');
    if (!token) {
        console.error('No authentication token found');
        throw new Error('No authentication token found');
    }

    try {
        console.log('Submitting invention for review...');
        const response = await fetch(`https://127.0.0.1:5000/api/inventions/${inventionId}/status`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            credentials: 'include',
            body: JSON.stringify({ status: 'pending' })
        });

        console.log('Response status:', response.status);
        if (!response.ok) {
            const errorData = await response.json();
            console.error('Server error:', errorData);
            throw new Error(errorData.message || 'Failed to submit invention');
        }

        const result = await response.json();
        console.log('Invention submitted successfully:', result);
        return result;
    } catch (error) {
        console.error('Error submitting invention:', error);
        throw error;
    }
}

// Function to create invention card HTML
function createInventionCard(invention) {
    const user = JSON.parse(localStorage.getItem('user'));
    const isInventor = user.role === 'inventor';
    const isOwner = invention.inventor_id === parseInt(user.id);

    return `
        <div class="invention-card" data-invention-id="${invention.id}">
            <h3>${invention.title}</h3>
            <p>${invention.description}</p>
            <div class="invention-meta">
                <span class="patent-status">Patent: ${invention.patent_status}</span>
                <span class="funding-status">Funding: ${invention.funding_status}</span>
                <span class="status">Status: ${invention.status}</span>
                <span class="date">Created: ${new Date(invention.created_at).toLocaleDateString()}</span>
            </div>
            <div class="card-actions">
                ${invention.status === 'draft' ? `
                    <button class="submit-invention-btn">Submit for Review</button>
                ` : ''}
                ${isInventor && isOwner ? `
                    <button class="delete-invention-btn">Delete Project</button>
                ` : ''}
            </div>
        </div>
    `;
}

// Function to create password confirmation modal
function createPasswordConfirmationModal() {
    return `
        <div class="modal" id="passwordConfirmationModal">
            <div class="modal-content">
                <div class="modal-header">
                    <h2 class="modal-title">Confirm Deletion</h2>
                    <button class="modal-close">&times;</button>
                </div>
                <div class="modal-body">
                    <p>Please enter your password to confirm deletion of this project.</p>
                    <form id="passwordConfirmationForm">
                        <div class="form-group">
                            <label for="password">Password</label>
                            <input type="password" id="password" name="password" required>
                        </div>
                        <div class="modal-actions">
                            <button type="button" class="cancel-btn">Cancel</button>
                            <button type="submit" class="confirm-btn">Confirm Delete</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    `;
}

// Function to handle invention deletion
async function handleInventionDeletion(inventionId, password) {
    const token = localStorage.getItem('token');
    if (!token) {
        throw new Error('No authentication token found');
    }

    try {
        const response = await fetch(`https://127.0.0.1:5000/api/inventions/${inventionId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            credentials: 'include',
            body: JSON.stringify({ password }),
            rejectUnauthorized: false
        });

        if (!response.ok) {
            const errorData = await response.json();
            console.error('Server error:', errorData);
            throw new Error(errorData.message || 'Failed to delete invention');
        }

        return await response.json();
    } catch (error) {
        console.error('Error deleting invention:', error);
        throw error;
    }
}

// Function to handle password confirmation modal
function handlePasswordConfirmationModal(inventionId) {
    // Remove existing modal if any
    const existingModal = document.getElementById('passwordConfirmationModal');
    if (existingModal) {
        existingModal.remove();
    }

    // Add new modal to body
    document.body.insertAdjacentHTML('beforeend', createPasswordConfirmationModal());

    // Get modal elements
    const modal = document.getElementById('passwordConfirmationModal');
    const closeBtn = modal.querySelector('.modal-close');
    const cancelBtn = modal.querySelector('.cancel-btn');
    const form = document.getElementById('passwordConfirmationForm');

    // Show modal
    modal.style.display = 'block';

    // Handle form submission
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const password = form.querySelector('#password').value;

        try {
            await handleInventionDeletion(inventionId, password);
            alert('Project deleted successfully!');
            modal.style.display = 'none';
            // Refresh the inventions list
            handleMenuClick('myInventions');
        } catch (error) {
            alert(error.message || 'Failed to delete project. Please try again.');
        }
    });

    // Close modal when clicking close button
    closeBtn.addEventListener('click', () => {
        modal.style.display = 'none';
    });

    // Close modal when clicking cancel button
    cancelBtn.addEventListener('click', () => {
        modal.style.display = 'none';
    });

    // Close modal when clicking outside
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.style.display = 'none';
        }
    });

    // Close modal with Escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && modal.style.display === 'block') {
            modal.style.display = 'none';
        }
    });
}

// Function to create modal HTML
function createInventionModal(invention) {
    return `
        <div class="modal" id="inventionModal">
            <div class="modal-content">
                <div class="modal-header">
                    <h2 class="modal-title">${invention.title}</h2>
                    <button class="modal-close">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="modal-meta">
                        <span class="modal-status">Patent Status: ${invention.patent_status}</span>
                        <span class="modal-status">Funding Status: ${invention.funding_status}</span>
                        <span class="modal-status">Status: ${invention.status}</span>
                        <span class="modal-status">Created: ${new Date(invention.created_at).toLocaleDateString()}</span>
                    </div>
                    <div class="modal-section">
                        <h3>Description</h3>
                        <div class="modal-description">${invention.description}</div>
                    </div>
                    <div class="modal-section">
                        <h3>Technical Details</h3>
                        <div class="modal-technical">${invention.technical_details}</div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Function to handle modal
function handleModal(invention) {
    // Remove existing modal if any
    const existingModal = document.getElementById('inventionModal');
    if (existingModal) {
        existingModal.remove();
    }

    // Add new modal to body
    document.body.insertAdjacentHTML('beforeend', createInventionModal(invention));

    // Get modal elements
    const modal = document.getElementById('inventionModal');
    const closeBtn = modal.querySelector('.modal-close');

    // Show modal
    modal.style.display = 'block';

    // Close modal when clicking close button
    closeBtn.addEventListener('click', () => {
        modal.style.display = 'none';
    });

    // Close modal when clicking outside
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.style.display = 'none';
        }
    });

    // Close modal with Escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && modal.style.display === 'block') {
            modal.style.display = 'none';
        }
    });
}

// Function to handle menu item click
async function handleMenuClick(menuId) {
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
    } else if (user.role === 'investor') {
        switch (menuId) {
            case 'availableProjects':
                try {
                    contentDiv.innerHTML = `
                        <div class="welcome-section">
                            <h1>Welcome, ${user.first_name}!</h1>
                            <h2>${roleConfigs[user.role].title}</h2>
                        </div>
                        <div class="dashboard-sections">
                            <div class="container">
                                <h2>Available Projects</h2>
                                <div class="inventions-grid" id="inventions-grid">
                                    <div class="loading">Loading available projects...</div>
                                </div>
                            </div>
                        </div>
                    `;

                    // Fetch and display available projects
                    const response = await fetch('https://127.0.0.1:5000/api/inventions/available', {
                        headers: {
                            'Authorization': `Bearer ${localStorage.getItem('token')}`,
                            'Accept': 'application/json'
                        },
                        credentials: 'include',
                        rejectUnauthorized: false
                    });

                    if (!response.ok) {
                        throw new Error('Failed to fetch available projects');
                    }

                    const data = await response.json();
                    const inventionsGrid = document.getElementById('inventions-grid');
                    inventionsGrid.innerHTML = data.projects.map(createInventionCard).join('');

                    // Add click event listeners to cards
                    document.querySelectorAll('.invention-card').forEach(card => {
                        card.addEventListener('click', async (e) => {
                            const inventionId = card.dataset.inventionId;
                            try {
                                const response = await fetch(`https://127.0.0.1:5000/api/inventions/${inventionId}`, {
                                    headers: {
                                        'Authorization': `Bearer ${localStorage.getItem('token')}`,
                                        'Accept': 'application/json'
                                    },
                                    credentials: 'include',
                                    rejectUnauthorized: false
                                });

                                if (response.status === 403) {
                                    alert('You do not have permission to view this invention.');
                                    return;
                                }

                                if (!response.ok) {
                                    throw new Error('Failed to fetch invention details');
                                }

                                const invention = await response.json();
                                handleModal(invention);
                            } catch (error) {
                                console.error('Error fetching invention details:', error);
                                if (error.message === 'Failed to fetch invention details') {
                                    alert('Failed to load invention details. Please try again.');
                                } else {
                                    alert('An error occurred while loading the invention details.');
                                }
                            }
                        });
                    });
                } catch (error) {
                    contentDiv.innerHTML = `
                        <div class="welcome-section">
                            <h1>Welcome, ${user.first_name}!</h1>
                            <h2>${roleConfigs[user.role].title}</h2>
                        </div>
                        <div class="dashboard-sections">
                            <div class="container">
                                <h2>Available Projects</h2>
                                <div class="error-message">
                                    Failed to load available projects. Please try again later.
                                </div>
                            </div>
                        </div>
                    `;
                }
                break;
            case 'myInvestments':
                contentDiv.innerHTML = `
                    <div class="welcome-section">
                        <h1>Welcome, ${user.first_name}!</h1>
                        <h2>${roleConfigs[user.role].title}</h2>
                    </div>
                    <div class="dashboard-sections">
                        <div class="container">
                            <h2>My Investments</h2>
                            <p>Investments made by you will be displayed here...</p>
                        </div>
                    </div>
                `;
                break;
            case 'investmentHistory':
                contentDiv.innerHTML = `
                    <div class="welcome-section">
                        <h1>Welcome, ${user.first_name}!</h1>
                        <h2>${roleConfigs[user.role].title}</h2>
                    </div>
                    <div class="dashboard-sections">
                        <div class="container">
                            <h2>Investment History</h2>
                            <p>Investment history will be displayed here...</p>
                        </div>
                    </div>
                `;
                break;
            case 'analytics':
                contentDiv.innerHTML = `
                    <div class="welcome-section">
                        <h1>Welcome, ${user.first_name}!</h1>
                        <h2>${roleConfigs[user.role].title}</h2>
                    </div>
                    <div class="dashboard-sections">
                        <div class="container">
                            <h2>Investment Analytics</h2>
                            <p>Investment analytics will be displayed here...</p>
                        </div>
                    </div>
                `;
                break;
        }
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
                try {
                    contentDiv.innerHTML = `
                        <div class="welcome-section">
                            <h1>Welcome, ${user.first_name}!</h1>
                            <h2>${roleConfigs[user.role].title}</h2>
                        </div>
                        <div class="dashboard-sections">
                            <div class="container">
                                <h2>My Inventions</h2>
                                <div class="inventions-grid" id="inventions-grid">
                                    <div class="loading">Loading inventions...</div>
                                </div>
                            </div>
                        </div>
                    `;

                    // Fetch and display inventions
                    const response = await fetch('https://127.0.0.1:5000/api/inventions', {
                        headers: {
                            'Authorization': `Bearer ${localStorage.getItem('token')}`,
                            'Accept': 'application/json'
                        },
                        credentials: 'include'
                    });

                    if (!response.ok) {
                        throw new Error('Failed to fetch inventions');
                    }

                    const data = await response.json();
                    const inventionsGrid = document.getElementById('inventions-grid');
                    inventionsGrid.innerHTML = data.inventions.map(createInventionCard).join('');

                    // Add click event listeners to cards
                    document.querySelectorAll('.invention-card').forEach(card => {
                        card.addEventListener('click', async (e) => {
                            // Don't trigger modal if clicking action buttons
                            if (e.target.classList.contains('submit-invention-btn') || 
                                e.target.classList.contains('delete-invention-btn')) {
                                return;
                            }
                            
                            const inventionId = card.dataset.inventionId;
                            try {
                                const response = await fetch(`https://127.0.0.1:5000/api/inventions/${inventionId}`, {
                                    headers: {
                                        'Authorization': `Bearer ${localStorage.getItem('token')}`,
                                        'Accept': 'application/json'
                                    },
                                    credentials: 'include',
                                    rejectUnauthorized: false
                                });

                                if (response.status === 403) {
                                    alert('You do not have permission to view this invention.');
                                    return;
                                }

                                if (!response.ok) {
                                    throw new Error('Failed to fetch invention details');
                                }

                                const invention = await response.json();
                                handleModal(invention);
                            } catch (error) {
                                console.error('Error fetching invention details:', error);
                                if (error.message === 'Failed to fetch invention details') {
                                    alert('Failed to load invention details. Please try again.');
                                } else {
                                    alert('An error occurred while loading the invention details.');
                                }
                            }
                        });
                    });

                    // Add click event listeners to submit buttons
                    document.querySelectorAll('.submit-invention-btn').forEach(btn => {
                        btn.addEventListener('click', async (e) => {
                            e.stopPropagation(); // Prevent card click event
                            const inventionId = btn.closest('.invention-card').dataset.inventionId;
                            try {
                                await handleInventionSubmission(inventionId);
                                alert('Invention submitted for review successfully!');
                                // Refresh the inventions list
                                handleMenuClick('myInventions');
                            } catch (error) {
                                alert('Failed to submit invention. Please try again.');
                            }
                        });
                    });

                    // Add click event listeners to delete buttons
                    document.querySelectorAll('.delete-invention-btn').forEach(btn => {
                        btn.addEventListener('click', (e) => {
                            e.stopPropagation(); // Prevent card click event
                            const inventionId = btn.closest('.invention-card').dataset.inventionId;
                            handlePasswordConfirmationModal(inventionId);
                        });
                    });
                } catch (error) {
                    contentDiv.innerHTML = `
                        <div class="welcome-section">
                            <h1>Welcome, ${user.first_name}!</h1>
                            <h2>${roleConfigs[user.role].title}</h2>
                        </div>
                        <div class="dashboard-sections">
                            <div class="container">
                                <h2>My Inventions</h2>
                                <div class="error-message">
                                    Failed to load inventions. Please try again later.
                                </div>
                            </div>
                        </div>
                    `;
                }
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