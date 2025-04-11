// Initialize PDF libraries
let pdfjsLib = null;
let PDFLib = null;

// Function to load PDF libraries
async function loadPDFLibraries() {
    try {
        // Load PDF.js
        const pdfjsScript = document.createElement('script');
        pdfjsScript.src = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js';
        await new Promise((resolve, reject) => {
            pdfjsScript.onload = resolve;
            pdfjsScript.onerror = reject;
            document.head.appendChild(pdfjsScript);
        });

        // Initialize PDF.js worker
        pdfjsLib = window.pdfjsLib;
        pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';

        // Load PDF-Lib
        const pdfLibScript = document.createElement('script');
        pdfLibScript.src = 'https://unpkg.com/pdf-lib@1.17.1';
        await new Promise((resolve, reject) => {
            pdfLibScript.onload = resolve;
            pdfLibScript.onerror = reject;
            document.head.appendChild(pdfLibScript);
        });

        PDFLib = window.PDFLib;
        console.log('PDF libraries loaded successfully');
    } catch (error) {
        console.error('Failed to load PDF libraries:', error);
        throw new Error('Failed to load PDF libraries. Please refresh the page.');
    }
}

// Function to check if PDF libraries are loaded
function arePDFLibrariesLoaded() {
    return pdfjsLib !== null && PDFLib !== null;
}

// Function to add watermark to PDF
async function addWatermarkToPDF(file) {
    console.log('Starting watermark process...');
    
    // Ensure libraries are loaded
    if (!arePDFLibrariesLoaded()) {
        console.log('Libraries not loaded, loading them now...');
        await loadPDFLibraries();
    }
    
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = async function(e) {
            try {
                console.log('File read successfully, processing PDF...');
                const typedarray = new Uint8Array(e.target.result);
                
                // Load the original PDF
                const originalPdf = await PDFLib.PDFDocument.load(typedarray);
                
                // Get inventor name from localStorage
                const user = JSON.parse(localStorage.getItem('user'));
                const inventorName = user ? user.first_name + ' ' + user.last_name : 'Unknown';
                
                // Create a canvas for the watermark
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                canvas.width = 800;  // Standard width
                canvas.height = 100; // Height for watermark text
                
                // Set watermark text style
                ctx.font = 'bold 28px Arial'; // Increased font size
                ctx.fillStyle = 'rgba(128, 128, 128, 0.5)'; // Increased opacity to 0.5
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                
                // Add watermark text with inventor name
                const watermarkText = `ELEVATEX - ${inventorName.toUpperCase()}`;
                ctx.fillText(watermarkText, canvas.width/2, canvas.height/2);
                
                // Convert canvas to image
                const watermarkImage = canvas.toDataURL('image/png');
                
                // Process each page
                for (let i = 0; i < originalPdf.getPageCount(); i++) {
                    const page = originalPdf.getPage(i);
                    const { width, height } = page.getSize();
                    
                    // Create watermark image
                    const watermarkImageBytes = await fetch(watermarkImage).then(res => res.arrayBuffer());
                    const watermarkImagePng = await originalPdf.embedPng(watermarkImageBytes);
                    
                    // Calculate dimensions for diagonal watermarks
                    const watermarkWidth = width * 0.4; // 40% of page width for each watermark
                    const watermarkHeight = watermarkWidth * 0.2; // Maintain aspect ratio
                    
                    // Calculate spacing for 4x3 grid
                    const rowSpacing = height / 5; // Divide height into 5 parts for 4 rows
                    const colSpacing = width / 4; // Divide width into 4 parts for 3 columns
                    
                    // Create 4x3 grid of watermarks
                    for (let row = 0; row < 4; row++) {
                        for (let col = 0; col < 3; col++) {
                            // Calculate position for each watermark
                            const y = rowSpacing * (row + 1);
                            const x = colSpacing * (col + 1) - (watermarkWidth / 2);
                            
                            // Draw the watermark with diagonal rotation
                            page.drawImage(watermarkImagePng, {
                                x,
                                y,
                                width: watermarkWidth,
                                height: watermarkHeight,
                                opacity: 0.5,
                                rotate: PDFLib.degrees(45) // 45-degree rotation for diagonal placement
                            });
                        }
                    }
                }
                
                // Save the watermarked PDF
                const watermarkedPdfBytes = await originalPdf.save();
                const watermarkedFile = new File([watermarkedPdfBytes], file.name, {
                    type: 'application/pdf'
                });
                
                console.log('Watermark process completed successfully');
                resolve(watermarkedFile);
            } catch (error) {
                console.error('Error during PDF processing:', error);
                reject(new Error('Failed to process PDF file. Please try again or contact support.'));
            }
        };
        reader.onerror = (error) => {
            console.error('Error reading file:', error);
            reject(new Error('Failed to read the PDF file.'));
        };
        reader.readAsArrayBuffer(file);
    });
}

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
                icon: '<svg xmlns="http://www.w3.org/2000/svg" height="24" viewBox="0 -960 960 960" width="24"><path d="M160-160v-640h160v640H160Zm240 0v-400h160v400H400Zm240 0v-240h160v240H640Z"/></svg>',
                text: 'My Investments',
                href: '#'
            },
            {
                id: 'messages',
                icon: '<svg xmlns="http://www.w3.org/2000/svg" height="24" viewBox="0 -960 960 960" width="24"><path d="M240-400h480v-80H240v80Zm0-120h480v-80H240v80Zm0-120h480v-80H240v80ZM80-80v-720q0-33 23.5-56.5T160-880h640q33 0 56.5 23.5T880-800v480q0 33-23.5 56.5T800-240H240L80-80Z"/></svg>',
                text: 'Messages',
                href: '#'
            },
            {
                id: 'notifications',
                icon: '<svg xmlns="http://www.w3.org/2000/svg" height="24" viewBox="0 -960 960 960" width="24"><path d="M160-200v-80h80v-280q0-83 50-147.5T420-792v-28q0-25 17.5-42.5T480-880q25 0 42.5 17.5T540-820v28q80 20 130 84.5T720-560v280h80v80H160Zm320-300Zm0 420q-33 0-56.5-23.5T400-160h160q0 33-23.5 56.5T480-80Z"/></svg>',
                text: 'My Notifications',
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
                id: 'messages',
                icon: '<svg xmlns="http://www.w3.org/2000/svg" height="24" viewBox="0 -960 960 960" width="24"><path d="M240-400h480v-80H240v80Zm0-120h480v-80H240v80Zm0-120h480v-80H240v80ZM80-80v-720q0-33 23.5-56.5T160-880h640q33 0 56.5 23.5T880-800v480q0 33-23.5 56.5T800-240H240L80-80Z"/></svg>',
                text: 'Messages',
                href: '#'
            },
            {
                id: 'notifications',
                icon: '<svg xmlns="http://www.w3.org/2000/svg" height="24" viewBox="0 -960 960 960" width="24"><path d="M160-200v-80h80v-280q0-83 50-147.5T420-792v-28q0-25 17.5-42.5T480-880q25 0 42.5 17.5T540-820v28q80 20 130 84.5T720-560v280h80v80H160Zm320-300Zm0 420q-33 0-56.5-23.5T400-160h160q0 33-23.5 56.5T480-80Z"/></svg>',
                text: 'My Notifications',
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
async function createIdeaSubmissionForm() {
    // Load PDF libraries when form is created
    try {
        await loadPDFLibraries();
    } catch (error) {
        console.error('Failed to load PDF libraries:', error);
    }

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
                    accept=".pdf">
                <small>Only PDF files are accepted. Max file size: 10MB each (50MB total)</small>
                <div id="selectedFiles" class="selected-files"></div>
                <div id="pdfLibraryStatus" class="pdf-library-status"></div>
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
    console.log('Starting idea submission...');

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
        console.log('Processing files:', files.length);
        
        for (const file of files) {
            if (file.type === 'application/pdf') {
                console.log('Processing PDF file:', file.name);
                try {
                    // Add watermark to PDF files
                    const watermarkedFile = await addWatermarkToPDF(file);
                    requestData.append('attachments', watermarkedFile);
                    console.log('PDF processed successfully:', file.name);
                } catch (error) {
                    console.error('Error processing PDF:', error);
                    alert('Failed to process PDF file. Please try again or contact support.');
                    return;
                }
            } else {
                requestData.append('attachments', file);
            }
        }
        
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
function createInventionCard(invention, section = 'available') {
    const user = JSON.parse(localStorage.getItem('user'));
    const isInvestor = user.role === 'investor';
    const isInventor = user.role === 'inventor';
    const isOwner = isInventor && invention.inventor_id === user.id;
    const isDraft = invention.status === 'draft';
    const isSubmitted = invention.status === 'submitted';
    const isAccepted = invention.status === 'accepted';
    const isRejected = invention.status === 'rejected';
    const hasPendingRequest = invention.has_pending_request;
    const hasAcceptedAccess = invention.has_accepted_access;

    // Detailed debug logging
    console.log('Creating card for invention:', {
        id: invention.id,
        title: invention.title,
        user: {
            id: user.id,
            role: user.role
        },
        invention: {
            inventor_id: invention.inventor_id,
            status: invention.status,
            has_pending_request: invention.has_pending_request,
            has_accepted_access: invention.has_accepted_access
        },
        flags: {
            isInvestor,
            isInventor,
            isOwner,
            isDraft,
            isSubmitted,
            isAccepted,
            isRejected,
            hasPendingRequest,
            hasAcceptedAccess
        },
        section
    });

    let buttonsHtml = '';
    
    // For investors
    if (isInvestor) {
        if (hasAcceptedAccess) {
            buttonsHtml = `
                <button class="view-details-btn" data-invention-id="${invention.id}">
                    View Details
                </button>
                <button class="start-chat-btn" data-invention-id="${invention.id}">
                    Start Chat
                </button>
            `;
        } else if (!hasPendingRequest) {
            buttonsHtml = `
                <button class="request-access-btn" data-invention-id="${invention.id}">
                    Request Access
                </button>
            `;
        } else {
            buttonsHtml = `
                <button class="request-access-btn disabled" data-invention-id="${invention.id}" disabled>
                    Request Sent
                </button>
            `;
        }
    }
    
    // For inventors
    if (isOwner) {
        if (isDraft) {
            buttonsHtml = `
                <button class="submit-invention-btn" data-invention-id="${invention.id}">
                    Submit for Review
                </button>
                <button class="delete-invention-btn" data-invention-id="${invention.id}">
                    Delete Invention
                </button>
            `;
        } else {
            buttonsHtml = `
                <button class="view-details-btn" data-invention-id="${invention.id}">
                    View Details
                </button>
                <button class="delete-invention-btn" data-invention-id="${invention.id}">
                    Delete Invention
                </button>
            `;
        }
    }

    // Log the final HTML being generated
    console.log('Generated buttons HTML:', buttonsHtml);

    return `
        <div class="invention-card" data-invention-id="${invention.id}">
            <h3>${invention.title}</h3>
            <p>${invention.description}</p>
            <div class="invention-meta">
                <span class="status">${invention.status}</span>
                <span class="date">Created: ${new Date(invention.created_at).toLocaleDateString()}</span>
            </div>
            ${buttonsHtml}
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
        <style>
            .modal {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.85);
                display: flex;
                justify-content: center;
                align-items: center;
                z-index: 1000;
                backdrop-filter: blur(5px);
            }
            .modal-content {
                background: #121212;
                padding: 30px;
                border-radius: 12px;
                width: 400px;
                border: 1px solid rgb(136, 135, 135);
                box-shadow: 0 0 30px rgba(240, 234, 233, 0.4);
                animation: slideIn 0.3s ease-out;
                font-family: Poppins, sans-serif;
            }
            @keyframes slideIn {
                from {
                    transform: translateY(-30px);
                    opacity: 0;
                }
                to {
                    transform: translateY(0);
                    opacity: 1;
                }
            }
            .modal-header {
                margin-bottom: 20px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .modal-title {
                margin: 0;
                color: #ffffff;
                font-size: 1.5em;
                font-weight: 600;
            }
            .modal-close {
                background: none;
                border: none;
                color: #e6e6ef;
                font-size: 1.5rem;
                cursor: pointer;
                padding: 0;
                line-height: 1;
            }
            .modal-body p {
                color: #b0b3c1;
                margin: 0 0 20px 0;
                font-size: 0.9em;
                line-height: 1.5;
            }
            .form-group {
                margin-bottom: 20px;
            }
            .form-group label {
                display: block;
                margin-bottom: 8px;
                color: #e6e6ef;
                font-size: 0.9em;
            }
            .form-group input[type="password"] {
                width: 100%;
                padding: 12px;
                border: 1px solid #ff4a2a !important;
                background-color: #1e1e1e;
                color: white;
                border-radius: 8px;
                font-size: 1em;
                box-sizing: border-box;
                transition: box-shadow 0.3s ease;
            }
            .form-group input[type="password"]:focus {
                outline: none !important;
                box-shadow: 0 0 0 3px rgba(255, 74, 42, 0.4) !important;
            }
            .modal-actions {
                display: flex;
                justify-content: flex-end;
                gap: 12px;
                margin-top: 20px;
            }
            .modal-actions button {
                padding: 10px 20px;
                border: none;
                border-radius: 8px;
                cursor: pointer;
                font-size: 0.9em;
                font-weight: 500;
                transition: all 0.2s;
                font-family: Poppins, sans-serif;
            }
            .modal-actions .cancel-btn {
                background: #2a2a2a;
                color: #e6e6ef;
                border: 1px solid #42434a;
            }
            .modal-actions .cancel-btn:hover {
                background: #333;
            }
            .modal-actions .confirm-btn {
                background: #ff4a2a !important;
                color: white !important;
            }
            .modal-actions .confirm-btn:hover {
                background: #e13a1a !important;
                transform: translateY(-1px);
                box-shadow: 0 2px 5px rgba(255, 74, 42, 0.4);
            }
            .modal-actions .confirm-btn:active {
                transform: translateY(0);
                box-shadow: none;
            }
        </style>
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

// Function to handle document viewing
async function handleViewDocument(s3Key) {
    try {
        console.log('Received S3 key:', s3Key);
        
        if (!s3Key) {
            throw new Error('No document path provided');
        }
        
        // Extract the S3 key from the full URL or use the key directly
        let actualS3Key = s3Key;
        if (s3Key.startsWith('s3://')) {
            actualS3Key = s3Key.replace('s3://elevatex-inventions/', '');
        }
        
        if (!actualS3Key) {
            throw new Error('Could not extract valid S3 key from URL');
        }
        
        // Create a new window/tab to display the document
        const documentWindow = window.open('', '_blank');
        
        // Set the document URL to our direct streaming endpoint
        const encodedKey = encodeURIComponent(actualS3Key);
        const documentUrl = `https://127.0.0.1:5000/api/files/files/${encodedKey}`;
        
        // Write the document to the new window with pdf.js viewer
        documentWindow.document.write(`
            <html>
                <head>
                    <title>Document Viewer</title>
                    <script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js"></script>
                    <script>pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';</script>
                    <style>
                        body { 
                            margin: 0; 
                            padding: 20px; 
                            font-family: Arial, sans-serif;
                            background-color: #f5f5f5;
                        }
                        .pdf-container {
                            width: 100%;
                            height: 100vh;
                            display: flex;
                            flex-direction: column;
                        }
                        #pdf-viewer {
                            flex: 1;
                            width: 100%;
                            border: none;
                            background: white;
                            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                            overflow-y: auto;
                        }
                        .error-message {
                            color: #dc3545;
                            padding: 20px;
                            text-align: center;
                            background: white;
                            border-radius: 4px;
                            margin: 20px 0;
                            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                        }
                        .loading {
                            text-align: center;
                            padding: 20px;
                            color: #666;
                        }
                        /* Disable right-click */
                        body {
                            -webkit-user-select: none;
                            -moz-user-select: none;
                            -ms-user-select: none;
                            user-select: none;
                        }
                        /* Disable text selection */
                        * {
                            -webkit-touch-callout: none;
                            -webkit-user-select: none;
                            -khtml-user-select: none;
                            -moz-user-select: none;
                            -ms-user-select: none;
                            user-select: none;
                        }
                        .page {
                            margin: 10px auto;
                            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                        }
                        .page canvas {
                            display: block;
                            margin: 0 auto;
                        }
                    </style>
                </head>
                <body>
                    <div class="pdf-container">
                        <div id="loading" class="loading">Loading document...</div>
                        <div id="error" class="error-message" style="display: none;"></div>
                        <div id="pdf-viewer"></div>
                    </div>
                    <script>
                        // Disable right-click
                        document.addEventListener('contextmenu', function(e) {
                            e.preventDefault();
                            return false;
                        });

                        // Disable keyboard shortcuts
                        document.addEventListener('keydown', function(e) {
                            // Disable Ctrl+S, Ctrl+P, Ctrl+Shift+I, F12
                            if (
                                (e.ctrlKey && e.key === 's') ||
                                (e.ctrlKey && e.key === 'p') ||
                                (e.ctrlKey && e.shiftKey && e.key === 'i') ||
                                e.key === 'F12'
                            ) {
                                e.preventDefault();
                                return false;
                            }
                        });

                        const pdfViewer = document.getElementById('pdf-viewer');
                        const loading = document.getElementById('loading');
                        const error = document.getElementById('error');

                        // Fetch the PDF with authentication
                        fetch("${documentUrl}", {
                            headers: {
                                'Authorization': 'Bearer ${localStorage.getItem('token')}',
                                'Accept': 'application/json'
                            },
                            credentials: 'include'
                        })
                        .then(response => {
                            if (!response.ok) {
                                throw new Error('Failed to fetch PDF');
                            }
                            return response.arrayBuffer();
                        })
                        .then(data => {
                            return pdfjsLib.getDocument({data: data}).promise;
                        })
                        .then(pdf => {
                            loading.style.display = 'none';
                            pdfViewer.style.display = 'block';
                            
                            // Render all pages
                            const renderPromises = [];
                            for (let pageNum = 1; pageNum <= pdf.numPages; pageNum++) {
                                renderPromises.push(
                                    pdf.getPage(pageNum).then(page => {
                                        const viewport = page.getViewport({scale: 1.2}); // Increased scale to 1.2
                                        const canvas = document.createElement('canvas');
                                        const context = canvas.getContext('2d');
                                        canvas.height = viewport.height;
                                        canvas.width = viewport.width;
                                        
                                        const renderContext = {
                                            canvasContext: context,
                                            viewport: viewport
                                        };
                                        
                                        const pageDiv = document.createElement('div');
                                        pageDiv.className = 'page';
                                        pageDiv.appendChild(canvas);
                                        pdfViewer.appendChild(pageDiv);
                                        
                                        return page.render(renderContext).promise;
                                    })
                                );
                            }
                            return Promise.all(renderPromises);
                        })
                        .catch(err => {
                            console.error('Error loading PDF:', err);
                            loading.style.display = 'none';
                            error.style.display = 'block';
                            error.textContent = 'Failed to load PDF document. Please try again.';
                        });
                    </script>
                </body>
            </html>
        `);
        
    } catch (error) {
        console.error('Error viewing document:', error);
        alert('Failed to view document. Please try again.');
    }
}

// Function to handle modal
function handleModal(invention) {
    // Remove existing modal if any
    const existingModal = document.getElementById('inventionModal');
    if (existingModal) {
        existingModal.remove();
    }

    // Debug logging for invention data
    console.log('Invention data:', invention);
    console.log('Documents:', invention.documents);

    // Add new modal to body
    document.body.insertAdjacentHTML('beforeend', createInventionModal(invention));

    // Get modal elements
    const modal = document.getElementById('inventionModal');
    const closeBtn = modal.querySelector('.modal-close');

    // Show modal
    modal.style.display = 'block';

    // Add event listeners for document view buttons
    modal.querySelectorAll('.view-document-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.stopPropagation(); // Prevent modal click event
            const s3Key = btn.dataset.filePath;
            
            try {
                await handleViewDocument(s3Key);
            } catch (error) {
                console.error('Error viewing document:', error);
                alert('Failed to view document. Please try again.');
            }
        });
    });

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

// Function to create modal HTML
function createInventionModal(invention) {
    // Debug logging for invention data
    console.log('Creating modal for invention:', invention);
    console.log('Documents in invention:', invention.documents);

    const user = JSON.parse(localStorage.getItem('user'));
    const isInvestor = user.role === 'investor';
    const isInventor = user.role === 'inventor';
    const isOwner = isInventor && invention.inventor_id === user.id;
    const hasAcceptedAccess = invention.has_accepted_access;

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
                    ${invention.documents && invention.documents.length > 0 ? `
                        <div class="modal-section">
                            <h3>Documents</h3>
                            <div class="documents-list">
                                ${invention.documents.map(doc => {
                                    console.log('Document data:', doc);
                                    return `
                                        <div class="document-item">
                                            <span class="document-name">${doc.filename}</span>
                                            ${(isOwner || (isInvestor && hasAcceptedAccess)) ? `
                                                <button class="view-document-btn" data-file-path="${doc.s3_key}">
                                                    View Document
                                                </button>
                                            ` : `
                                                <span class="access-restricted">Access Restricted</span>
                                            `}
                                        </div>
                                    `;
                                }).join('')}
                            </div>
                        </div>
                    ` : ''}
                </div>
            </div>
        </div>
    `;
}

// Function to handle request access
async function handleRequestAccess(inventionId) {
    try {
        const response = await fetch(`https://127.0.0.1:5000/api/inventions/${inventionId}/request-access`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`,
                'Accept': 'application/json'
            },
            credentials: 'include',
            rejectUnauthorized: false
        });

        const data = await response.json();

        if (!response.ok) {
            if (response.status === 403) {
                alert('Only investors can request access to inventions.');
                return;
            }
            if (response.status === 400) {
                alert(data.error || 'You have already requested access to this invention.');
                return;
            }
            if (response.status === 404) {
                alert('Invention not found.');
                return;
            }
            throw new Error(data.error || 'Failed to request access');
        }

        alert('Access request sent successfully!');
        // Disable the request button
        const button = document.querySelector(`.request-access-btn[data-invention-id="${inventionId}"]`);
        if (button) {
            button.disabled = true;
            button.textContent = 'Request Sent';
        }
    } catch (error) {
        console.error('Error requesting access:', error);
        alert(error.message || 'Failed to request access. Please try again.');
    }
}

// Function to handle menu item click
async function handleMenuClick(menuId, chatId = null) {
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
    } else if (menuId === 'security') {
        try {
            const token = localStorage.getItem('token');
            if (!token) {
                throw new Error('You must be logged in to view security logs');
            }

            // Fetch security logs
            const response = await fetch('https://127.0.0.1:5000/api/admin/security-logs', {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Accept': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error('Failed to fetch security logs');
            }

            const data = await response.json();
            
            // Check if we have logs data
            if (!data.logs || !Array.isArray(data.logs)) {
                throw new Error('Invalid response format from server');
            }

            const logs = data.logs;

            // Create HTML for security logs
            contentDiv.innerHTML = `
                <div class="welcome-section">
                    <h1>Security Logs</h1>
                    <h2>${roleConfigs[user.role].title}</h2>
                </div>
                <div class="dashboard-sections">
                    <div class="container">
                        <div class="security-logs-container">
                            <div class="filters">
                                <div class="filter-group">
                                    <label for="eventTypeFilter">Event Type</label>
                                    <select id="eventTypeFilter">
                                        <option value="">All Event Types</option>
                                        <option value="login_attempt">Login Attempts</option>
                                        <option value="account_lock">Account Locks</option>
                                        <option value="document_access">Document Access</option>
                                        <option value="document_upload">Document Upload</option>
                                        <option value="document_delete">Document Delete</option>
                                        <option value="password_change">Password Changes</option>
                                        <option value="role_change">Role Changes</option>
                                    </select>
                                </div>
                                <div class="filter-group">
                                    <label for="statusFilter">Status</label>
                                    <select id="statusFilter">
                                        <option value="">All Statuses</option>
                                        <option value="success">Success</option>
                                        <option value="failure">Failure</option>
                                        <option value="warning">Warning</option>
                                    </select>
                                </div>
                                <div class="filter-group">
                                    <label for="startDateFilter">Start Date</label>
                                    <input type="date" id="startDateFilter" class="date-input">
                                </div>
                                <div class="filter-group">
                                    <label for="endDateFilter">End Date</label>
                                    <input type="date" id="endDateFilter" class="date-input">
                                </div>
                                <button id="applyFilters" class="filter-button">Apply Filters</button>
                            </div>
                            <div class="logs-table">
                                <table>
                                    <thead>
                                        <tr>
                                            <th>Timestamp</th>
                                            <th>Event Type</th>
                                            <th>User ID</th>
                                            <th>IP Address</th>
                                            <th>Status</th>
                                            <th>Details</th>
                                        </tr>
                                    </thead>
                                    <tbody id="logsTableBody">
                                        ${logs.length > 0 ? logs.map(log => {
                                            let details = log.details || 'N/A';
                                            const rowClass = log.status === 'warning' ? 'warning-row' : 
                                                           log.status === 'success' ? 'success-row' : 
                                                           log.status === 'failure' ? 'failure-row' : '';
                                            return `
                                                <tr class="${rowClass}">
                                                    <td>${new Date(log.timestamp).toLocaleString()}</td>
                                                    <td>${log.event_type}</td>
                                                    <td>${log.user_id || 'N/A'}</td>
                                                    <td>${log.ip_address || 'N/A'}</td>
                                                    <td class="status-${log.status}">${log.status}</td>
                                                    <td>${details}</td>
                                                </tr>
                                            `;
                                        }).join('') : '<tr><td colspan="6" class="no-logs">No security logs found</td></tr>'}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
                <style>
                    .security-logs-container {
                        background: #1e1e1e;
                        border-radius: 8px;
                        padding: 20px;
                        margin-top: 20px;
                    }
                    .filters {
                        display: flex;
                        gap: 15px;
                        flex-wrap: wrap;
                        margin-bottom: 20px;
                        padding: 15px;
                        background: #2a2a2a;
                        border-radius: 6px;
                    }
                    .filter-group {
                        display: flex;
                        flex-direction: column;
                        gap: 5px;
                    }
                    .filter-group label {
                        color: #e6e6ef;
                        font-size: 0.9em;
                    }
                    .filter-group select, .filter-group input {
                        padding: 8px 12px;
                        border: 1px solid #42434a;
                        background: #1e1e1e;
                        color: white;
                        border-radius: 4px;
                        min-width: 150px;
                    }
                    .filter-button {
                        padding: 8px 20px;
                        background: #ff4a2a;
                        color: white;
                        border: none;
                        border-radius: 4px;
                        cursor: pointer;
                        align-self: flex-end;
                        margin-top: 22px;
                    }
                    .filter-button:hover {
                        background: #e13a1a;
                    }
                    .logs-table {
                        overflow-x: auto;
                    }
                    .logs-table table {
                        width: 100%;
                        border-collapse: collapse;
                    }
                    .logs-table th {
                        background: #2a2a2a;
                        color: #e6e6ef;
                        padding: 12px;
                        text-align: left;
                    }
                    .logs-table td {
                        padding: 12px;
                        border-bottom: 1px solid #42434a;
                        color: #b0b3c1;
                    }
                    .logs-table tr:hover {
                        background: #2a2a2a;
                    }
                    .status-success {
                        color: #28a745;
                        font-weight: bold;
                    }
                    .status-failure {
                        color: #fd7e14;
                        font-weight: bold;
                    }
                    .status-warning {
                        color: #dc3545;
                        font-weight: bold;
                    }
                    .logs-table tr.success-row {
                        border-left: 4px solid #28a745;
                        background-color: rgba(40, 167, 69, 0.05);
                    }
                    .logs-table tr.failure-row {
                        border-left: 4px solid #fd7e14;
                        background-color: rgba(253, 126, 20, 0.05);
                    }
                    .logs-table tr.warning-row {
                        border-left: 4px solid #dc3545;
                        background-color: rgba(220, 53, 69, 0.05);
                    }
                    .no-logs {
                        text-align: center;
                        color: #6c757d;
                        padding: 20px;
                    }
                </style>
            `;

            // Add event listeners for filters
            document.getElementById('applyFilters').addEventListener('click', async () => {
                const eventType = document.getElementById('eventTypeFilter').value;
                const status = document.getElementById('statusFilter').value;
                const startDate = document.getElementById('startDateFilter').value;
                const endDate = document.getElementById('endDateFilter').value;

                const queryParams = new URLSearchParams();
                if (eventType) queryParams.append('event_type', eventType);
                if (status) queryParams.append('status', status);
                if (startDate) queryParams.append('start_date', startDate);
                if (endDate) queryParams.append('end_date', endDate);

                const filteredResponse = await fetch(`https://127.0.0.1:5000/api/admin/security-logs?${queryParams.toString()}`, {
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Accept': 'application/json'
                    }
                });

                if (!filteredResponse.ok) {
                    throw new Error('Failed to fetch filtered security logs');
                }

                const filteredData = await filteredResponse.json();
                
                // Check if we have filtered logs data
                if (!filteredData.logs || !Array.isArray(filteredData.logs)) {
                    throw new Error('Invalid response format from server');
                }

                const filteredLogs = filteredData.logs;

                document.getElementById('logsTableBody').innerHTML = filteredLogs.length > 0 ? filteredLogs.map(log => `
                    <tr class="${log.status === 'warning' ? 'warning-row' : log.status === 'success' ? 'success-row' : log.status === 'failure' ? 'failure-row' : ''}">
                        <td>${new Date(log.timestamp).toLocaleString()}</td>
                        <td>${log.event_type}</td>
                        <td>${log.user_id || 'N/A'}</td>
                        <td>${log.ip_address || 'N/A'}</td>
                        <td class="status-${log.status}">${log.status}</td>
                        <td>${log.details || 'N/A'}</td>
                    </tr>
                `).join('') : '<tr><td colspan="6" class="no-logs">No security logs found</td></tr>';
            });

        } catch (error) {
            console.error('Error loading security logs:', error);
            contentDiv.innerHTML = `
                <div class="error-message">
                    <h2>Error Loading Security Logs</h2>
                    <p>${error.message}</p>
                </div>
            `;
        }
    } else if (menuId === 'messages') {
        try {
            const token = localStorage.getItem('token');
            if (!token) {
                throw new Error('You must be logged in to view messages');
            }

            // First, ensure chat component is loaded
            const chatLoaded = await loadChatComponent();
            if (!chatLoaded) {
                throw new Error('Failed to load chat component');
            }

            // Prompt for password before proceeding
            try {
                const password = await promptForPassword();
                if (!password) {
                    throw new Error('Password is required to access messages');
                }

                // Fetch messages
                const response = await fetch('https://127.0.0.1:5000/api/messages/chats', {
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Accept': 'application/json'
                    },
                    credentials: 'include'
                });

                if (!response.ok) {
                    throw new Error('Failed to fetch messages');
                }

                const data = await response.json();
                console.log('Received messages:', data);

                // Create messages container if it doesn't exist
                let messagesContainer = document.getElementById('messages-container');
                if (!messagesContainer) {
                    contentDiv.innerHTML = `
                        <div class="messages-container" id="messages-container">
                            <div class="messages-sidebar">
                                <div class="messages-list" id="messages-list">
                                    <div class="loading">Loading messages...</div>
                                </div>
                            </div>
                            <div class="messages-main">
                                <div class="chat-container" id="chat-container">
                                    <div class="chat-placeholder">
                                        Select a chat to start messaging
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                }

                const messagesList = document.getElementById('messages-list');
                if (!messagesList) {
                    throw new Error('Messages list element not found');
                }

                if (data.chats && data.chats.length > 0) {
                    messagesList.innerHTML = data.chats.map(chat => `
                        <div class="chat-item" data-chat-id="${chat.id}" data-other-user-id="${chat.other_user_id}">
                            <h4>${chat.title}</h4>
                            <p>${chat.other_user_name} (${chat.other_user_role})</p>
                            <small>${chat.last_message_at ? new Date(chat.last_message_at).toLocaleString() : 'No messages yet'}</small>
                        </div>
                    `).join('');

                    // Add click handlers to chat items
                    document.querySelectorAll('.chat-item').forEach(item => {
                        item.addEventListener('click', async () => {
                            const chatId = item.getAttribute('data-chat-id');
                            const otherUserId = item.getAttribute('data-other-user-id');
                            
                            if (!chatId || !otherUserId) {
                                console.error('Missing required chat data:', { chatId, otherUserId });
                                return;
                            }
                            
                            // Clear the placeholder and set up chat UI
                            const chatContainer = document.getElementById('chat-container');
                            if (!chatContainer) {
                                throw new Error('Chat container not found');
                            }

                            chatContainer.innerHTML = `
                                <div class="chat-messages"></div>
                                <div class="chat-input">
                                    <textarea placeholder="Type your message..." rows="3"></textarea>
                                    <button class="send-button">Send</button>
                                </div>
                            `;
                            
                            // Initialize the chat with the password
                            const chat = new Chat('chat-container');
                            
                            // Get the password hash from the server
                            try {
                                const response = await fetch('https://127.0.0.1:5000/api/auth/password-hash', {
                                    method: 'POST',
                                    headers: {
                                        'Authorization': `Bearer ${token}`,
                                        'Content-Type': 'application/json'
                                    },
                                    body: JSON.stringify({ password: password })
                                });

                                if (!response.ok) {
                                    throw new Error('Failed to get password hash');
                                }

                                const data = await response.json();
                                // Store the password hash in localStorage
                                localStorage.setItem('password_hash', data.password_hash);
                            } catch (error) {
                                console.error('Error getting password hash:', error);
                                throw error;
                            }

                            await chat.initialize(chatId, otherUserId);
                        });
                    });
                } else {
                    messagesList.innerHTML = '<div class="no-messages">No messages yet</div>';
                }

            } catch (error) {
                console.error('Error accessing messages:', error);
                contentDiv.innerHTML = `
                    <div class="error-message">
                        ${error.message}
                    </div>
                `;
            }

        } catch (error) {
            console.error('Error:', error);
            contentDiv.innerHTML = `
                <div class="welcome-section">
                    <h1>Welcome, ${user.first_name}!</h1>
                    <h2>${roleConfigs[user.role].title}</h2>
                </div>
                <div class="dashboard-sections">
                    <div class="container">
                        <h2>Messages</h2>
                        <div class="error-message">
                            Failed to load messages: ${error.message}
                        </div>
                    </div>
                </div>
            `;
        }
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

                    console.log('Fetching available projects...');
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
                    console.log('Received projects data:', data);
                    
                    const inventionsGrid = document.getElementById('inventions-grid');
                    console.log('Creating cards for projects:', data.projects);
                    
                    inventionsGrid.innerHTML = data.projects.map(project => {
                        console.log('Processing project:', project);
                        return createInventionCard(project, 'available');
                    }).join('');

                    // Add click event listeners to cards
                    document.querySelectorAll('.invention-card').forEach(card => {
                        card.addEventListener('click', async (e) => {
                            const inventionId = card.dataset.inventionId;
                            try {
                                console.log('Fetching details for invention:', inventionId);
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
                                console.log('Received invention details:', invention);
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

                    // Add click event listeners to request access buttons
                    document.querySelectorAll('.request-access-btn').forEach(btn => {
                        btn.addEventListener('click', (e) => {
                            e.stopPropagation();
                            const inventionId = btn.dataset.inventionId;
                            handleRequestAccess(inventionId);
                        });
                    });

                    // Add click event listeners to start chat buttons
                    document.querySelectorAll('.start-chat-btn').forEach(btn => {
                        btn.addEventListener('click', async (e) => {
                            e.stopPropagation();
                            const inventionId = btn.dataset.inventionId;
                            console.log('Start chat clicked for invention:', inventionId);
                            
                            try {
                                await handleStartChat(inventionId);
                            } catch (error) {
                                console.error('Error starting chat:', error);
                                alert('Failed to start chat: ' + error.message);
                            }
                        });
                    });
                } catch (error) {
                    console.error('Error:', error);
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
                try {
                    contentDiv.innerHTML = `
                        <div class="welcome-section">
                            <h1>Welcome, ${user.first_name}!</h1>
                            <h2>${roleConfigs[user.role].title}</h2>
                        </div>
                        <div class="dashboard-sections">
                            <div class="container">
                                <h2>My Investments</h2>
                                <div class="inventions-grid" id="investments-grid">
                                    <div class="loading">Loading your investments...</div>
                                </div>
                            </div>
                        </div>
                    `;

                    const response = await fetch('https://127.0.0.1:5000/api/inventions/my-investments', {
                        headers: {
                            'Authorization': `Bearer ${localStorage.getItem('token')}`,
                            'Accept': 'application/json'
                        },
                        credentials: 'include',
                        rejectUnauthorized: false
                    });

                    if (!response.ok) {
                        throw new Error('Failed to fetch investments');
                    }

                    const data = await response.json();
                    const investmentsGrid = document.getElementById('investments-grid');
                    
                    if (data.investments.length === 0) {
                        investmentsGrid.innerHTML = `
                            <div class="no-investments">
                                <p>You haven't invested in any projects yet.</p>
                                <p>Browse available projects to find investment opportunities.</p>
                            </div>
                        `;
                    } else {
                        investmentsGrid.innerHTML = data.investments.map(investment => {
                            return createInventionCard(investment, 'investments');
                        }).join('');

                        // Add click event listeners to view details buttons
                        document.querySelectorAll('.view-details-btn').forEach(btn => {
                            btn.addEventListener('click', async (e) => {
                                e.stopPropagation();
                                const inventionId = btn.dataset.inventionId;
                                try {
                                    const response = await fetch(`https://127.0.0.1:5000/api/inventions/${inventionId}`, {
                                        headers: {
                                            'Authorization': `Bearer ${localStorage.getItem('token')}`,
                                            'Accept': 'application/json'
                                        },
                                        credentials: 'include',
                                        rejectUnauthorized: false
                                    });

                                    if (!response.ok) {
                                        throw new Error('Failed to fetch invention details');
                                    }

                                    const invention = await response.json();
                                    handleModal(invention);
                                } catch (error) {
                                    console.error('Error fetching invention details:', error);
                                    alert('Failed to load invention details. Please try again.');
                                }
                            });
                        });

                        // Add click event listeners to start chat buttons
                        document.querySelectorAll('.start-chat-btn').forEach(btn => {
                            btn.addEventListener('click', (e) => {
                                e.stopPropagation();
                                const inventionId = btn.dataset.inventionId;
                                handleStartChat(inventionId);
                            });
                        });
                    }
                } catch (error) {
                    console.error('Error:', error);
                    contentDiv.innerHTML = `
                        <div class="welcome-section">
                            <h1>Welcome, ${user.first_name}!</h1>
                            <h2>${roleConfigs[user.role].title}</h2>
                        </div>
                        <div class="dashboard-sections">
                            <div class="container">
                                <h2>My Investments</h2>
                                <div class="error-message">
                                    Failed to load your investments. Please try again later.
                                </div>
                            </div>
                        </div>
                    `;
                }
                break;
            case 'notifications':
                try {
                    contentDiv.innerHTML = `
                        <div class="welcome-section">
                            <h1>Welcome, ${user.first_name}!</h1>
                            <h2>${roleConfigs[user.role].title}</h2>
                        </div>
                        <div class="dashboard-sections">
                            <div class="container">
                                <h2>My Notifications</h2>
                                <div class="notifications-list" id="notifications-list">
                                    <div class="loading">Loading notifications...</div>
                                </div>
                            </div>
                        </div>
                    `;

                    const token = localStorage.getItem('token');
                    if (!token) {
                        throw new Error('No authentication token found');
                    }

                    console.log('Fetching notifications with token:', token);
                    
                    const response = await fetch('https://127.0.0.1:5000/api/notification/notifications', {
                        method: 'GET',
                        headers: {
                            'Authorization': `Bearer ${token}`,
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        },
                        credentials: 'include',
                        rejectUnauthorized: false
                    });

                    if (!response.ok) {
                        const errorData = await response.json();
                        console.error('Error response:', errorData);
                        throw new Error(errorData.message || 'Failed to fetch notifications');
                    }

                    const data = await response.json();
                    console.log('Received notifications:', data);
                    const notificationsList = document.getElementById('notifications-list');
                    
                    if (data.notifications.length === 0) {
                        notificationsList.innerHTML = '<div class="no-notifications">No notifications</div>';
                    } else {
                        notificationsList.innerHTML = data.notifications.map(notification => {
                            return `
                                <div class="notification-item ${notification.is_read ? 'read' : 'unread'}" 
                                     data-notification-id="${notification.id}"
                                     data-type="${notification.type}"
                                     data-reference-id="${notification.reference_id}"
                                     data-invention-id="${notification.invention_id}">
                                    <div class="notification-content">
                                        <h3>${notification.title}</h3>
                                        <p>${notification.message}</p>
                                        <span class="notification-date">${new Date(notification.created_at).toLocaleString()}</span>
                                    </div>
                                    ${notification.type === 'access_request' ? `
                                        <div class="notification-actions">
                                            ${notification.status === 'accepted' ? `
                                                <button class="accept-request-btn" disabled>Accepted</button>
                                                <button class="reject-request-btn" data-invention-id="${notification.invention_id}">Reject</button>
                                                <span class="status-text" style="color: #28a745;">Access request has been accepted</span>
                                            ` : notification.status === 'rejected' ? `
                                                <button class="accept-request-btn" data-invention-id="${notification.invention_id}">Accept</button>
                                                <button class="reject-request-btn" disabled>Rejected</button>
                                                <span class="status-text" style="color: #dc3545;">Access request has been rejected</span>
                                            ` : `
                                                <button class="accept-request-btn" data-invention-id="${notification.invention_id}">Accept</button>
                                                <button class="reject-request-btn" data-invention-id="${notification.invention_id}">Reject</button>
                                            `}
                                        </div>
                                    ` : ''}
                                </div>
                            `;
                        }).join('');

                        // Add event listeners for accept buttons
                        document.querySelectorAll('.accept-request-btn:not([disabled])').forEach(btn => {
                            btn.addEventListener('click', (e) => {
                                e.stopPropagation();
                                const notificationId = btn.closest('.notification-item').dataset.notificationId;
                                handleAccessRequestResponse(notificationId, 'accept');
                            });
                        });

                        // Add event listeners for reject buttons
                        document.querySelectorAll('.reject-request-btn:not([disabled])').forEach(btn => {
                            btn.addEventListener('click', (e) => {
                                e.stopPropagation();
                                const notificationId = btn.closest('.notification-item').dataset.notificationId;
                                handleAccessRequestResponse(notificationId, 'reject');
                            });
                        });
                    }
                } catch (error) {
                    console.error('Error:', error);
                    contentDiv.innerHTML = `
                        <div class="welcome-section">
                            <h1>Welcome, ${user.first_name}!</h1>
                            <h2>${roleConfigs[user.role].title}</h2>
                        </div>
                        <div class="dashboard-sections">
                            <div class="container">
                                <h2>My Notifications</h2>
                                <div class="error-message">
                                    Failed to load notifications. Please try again later.
                                </div>
                            </div>
                        </div>
                    `;
                }
                break;
        }
    } else if (user.role === 'inventor') {
        switch (menuId) {
            case 'addProject':
                try {
                    // First load PDF libraries
                    await loadPDFLibraries();
                    console.log('PDF libraries loaded successfully');

                    contentDiv.innerHTML = `
                        <div class="welcome-section">
                            <h1>Welcome, ${user.first_name}!</h1>
                            <h2>${roleConfigs[user.role].title}</h2>
                        </div>
                        <div class="dashboard-sections">
                            <div class="container">
                                <h2>Add New Project</h2>
                                ${await createIdeaSubmissionForm()}
                            </div>
                        </div>
                    `;

                    // Add form submission handler
                    const form = document.getElementById('ideaSubmissionForm');
                    if (form) {
                        form.addEventListener('submit', handleIdeaSubmission);
                        
                        // Add file input change handler
                        const fileInput = form.querySelector('#attachments');
                        if (fileInput) {
                            fileInput.addEventListener('change', async (e) => {
                                const files = e.target.files;
                                const selectedFilesDiv = document.getElementById('selectedFiles');
                                if (selectedFilesDiv) {
                                    selectedFilesDiv.innerHTML = Array.from(files)
                                        .map(file => `<div>${file.name} (${(file.size / 1024 / 1024).toFixed(2)} MB)</div>`)
                                        .join('');
                                }
                            });
                        }
                    }

                } catch (error) {
                    console.error('Error:', error);
                    contentDiv.innerHTML = `
                        <div class="welcome-section">
                            <h1>Welcome, ${user.first_name}!</h1>
                            <h2>${roleConfigs[user.role].title}</h2>
                        </div>
                        <div class="dashboard-sections">
                            <div class="container">
                                <h2>Add New Project</h2>
                                <div class="error-message">
                                    Failed to load the form. Please try again later. Error: ${error.message}
                                </div>
                            </div>
                        </div>
                    `;
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
                                    <div class="loading">Loading your inventions...</div>
                                </div>
                            </div>
                        </div>
                    `;

                    const response = await fetch('https://127.0.0.1:5000/api/inventions', {
                        headers: {
                            'Authorization': `Bearer ${localStorage.getItem('token')}`,
                            'Accept': 'application/json'
                        },
                        credentials: 'include',
                        rejectUnauthorized: false
                    });

                    if (!response.ok) {
                        throw new Error('Failed to fetch inventions');
                    }

                    const data = await response.json();
                    const inventionsGrid = document.getElementById('inventions-grid');
                    
                    if (data.inventions.length === 0) {
                        inventionsGrid.innerHTML = `
                            <div class="no-inventions">
                                <p>You haven't created any projects yet.</p>
                                <p>Click "Add New Project" to get started.</p>
                            </div>
                        `;
                    } else {
                        inventionsGrid.innerHTML = data.inventions.map(invention => {
                            return createInventionCard(invention, 'inventions');
                        }).join('');

                        // Add click event listeners to view details buttons
                        document.querySelectorAll('.view-details-btn').forEach(btn => {
                            btn.addEventListener('click', async (e) => {
                                e.stopPropagation();
                                const inventionId = btn.dataset.inventionId;
                                try {
                                    const response = await fetch(`https://127.0.0.1:5000/api/inventions/${inventionId}`, {
                                        headers: {
                                            'Authorization': `Bearer ${localStorage.getItem('token')}`,
                                            'Accept': 'application/json'
                                        },
                                        credentials: 'include',
                                        rejectUnauthorized: false
                                    });

                                    if (!response.ok) {
                                        throw new Error('Failed to fetch invention details');
                                    }

                                    const invention = await response.json();
                                    handleModal(invention);
                                } catch (error) {
                                    console.error('Error fetching invention details:', error);
                                    alert('Failed to load invention details. Please try again.');
                                }
                            });
                        });

                        // Add click event listeners to delete buttons
                        document.querySelectorAll('.delete-invention-btn').forEach(btn => {
                            btn.addEventListener('click', (e) => {
                                e.stopPropagation();
                                const inventionId = btn.dataset.inventionId;
                                handleDeleteInvention(inventionId);
                            });
                        });

                        // Add click event listeners to submit for review buttons
                        document.querySelectorAll('.submit-invention-btn').forEach(btn => {
                            btn.addEventListener('click', async (e) => {
                                e.stopPropagation();
                                const inventionId = btn.dataset.inventionId;
                                try {
                                    await handleInventionSubmission(inventionId);
                                    alert('Invention submitted for review successfully!');
                                    // Refresh the inventions list
                                    handleMenuClick('myInventions');
                                } catch (error) {
                                    console.error('Error submitting invention:', error);
                                    alert(error.message || 'Failed to submit invention for review. Please try again.');
                                }
                            });
                        });
                    }
                } catch (error) {
                    console.error('Error:', error);
                    contentDiv.innerHTML = `
                        <div class="welcome-section">
                            <h1>Welcome, ${user.first_name}!</h1>
                            <h2>${roleConfigs[user.role].title}</h2>
                        </div>
                        <div class="dashboard-sections">
                            <div class="container">
                                <h2>My Inventions</h2>
                                <div class="error-message">
                                    Failed to load your inventions. Please try again later.
                                </div>
                            </div>
                        </div>
                    `;
                }
                break;
            case 'notifications':
                try {
                    contentDiv.innerHTML = `
                        <div class="welcome-section">
                            <h1>Welcome, ${user.first_name}!</h1>
                            <h2>${roleConfigs[user.role].title}</h2>
                        </div>
                        <div class="dashboard-sections">
                            <div class="container">
                                <h2>My Notifications</h2>
                                <div class="notifications-list" id="notifications-list">
                                    <div class="loading">Loading notifications...</div>
                                </div>
                            </div>
                        </div>
                    `;

                    const token = localStorage.getItem('token');
                    if (!token) {
                        throw new Error('No authentication token found');
                    }

                    console.log('Fetching notifications with token:', token);
                    
                    const response = await fetch('https://127.0.0.1:5000/api/notification/notifications', {
                        method: 'GET',
                        headers: {
                            'Authorization': `Bearer ${token}`,
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        },
                        credentials: 'include',
                        rejectUnauthorized: false
                    });

                    if (!response.ok) {
                        const errorData = await response.json();
                        console.error('Error response:', errorData);
                        throw new Error(errorData.message || 'Failed to fetch notifications');
                    }

                    const data = await response.json();
                    console.log('Received notifications:', data);
                    const notificationsList = document.getElementById('notifications-list');
                    
                    if (data.notifications.length === 0) {
                        notificationsList.innerHTML = '<div class="no-notifications">No notifications</div>';
                    } else {
                        notificationsList.innerHTML = data.notifications.map(notification => {
                            return `
                                <div class="notification-item ${notification.is_read ? 'read' : 'unread'}" 
                                     data-notification-id="${notification.id}"
                                     data-type="${notification.type}"
                                     data-reference-id="${notification.reference_id}"
                                     data-invention-id="${notification.invention_id}">
                                    <div class="notification-content">
                                        <h3>${notification.title}</h3>
                                        <p>${notification.message}</p>
                                        <span class="notification-date">${new Date(notification.created_at).toLocaleString()}</span>
                                    </div>
                                    ${notification.type === 'access_request' ? `
                                        <div class="notification-actions">
                                            ${notification.status === 'accepted' ? `
                                                <button class="accept-request-btn" disabled>Accepted</button>
                                                <button class="reject-request-btn" data-invention-id="${notification.invention_id}">Reject</button>
                                                <span class="status-text" style="color: #28a745;">Access request has been accepted</span>
                                            ` : notification.status === 'rejected' ? `
                                                <button class="accept-request-btn" data-invention-id="${notification.invention_id}">Accept</button>
                                                <button class="reject-request-btn" disabled>Rejected</button>
                                                <span class="status-text" style="color: #dc3545;">Access request has been rejected</span>
                                            ` : `
                                                <button class="accept-request-btn" data-invention-id="${notification.invention_id}">Accept</button>
                                                <button class="reject-request-btn" data-invention-id="${notification.invention_id}">Reject</button>
                                            `}
                                        </div>
                                    ` : ''}
                                </div>
                            `;
                        }).join('');

                        // Add event listeners for accept buttons
                        document.querySelectorAll('.accept-request-btn:not([disabled])').forEach(btn => {
                            btn.addEventListener('click', (e) => {
                                e.stopPropagation();
                                const notificationId = btn.closest('.notification-item').dataset.notificationId;
                                handleAccessRequestResponse(notificationId, 'accept');
                            });
                        });

                        // Add event listeners for reject buttons
                        document.querySelectorAll('.reject-request-btn:not([disabled])').forEach(btn => {
                            btn.addEventListener('click', (e) => {
                                e.stopPropagation();
                                const notificationId = btn.closest('.notification-item').dataset.notificationId;
                                handleAccessRequestResponse(notificationId, 'reject');
                            });
                        });
                    }
                } catch (error) {
                    console.error('Error:', error);
                    contentDiv.innerHTML = `
                        <div class="welcome-section">
                            <h1>Welcome, ${user.first_name}!</h1>
                            <h2>${roleConfigs[user.role].title}</h2>
                        </div>
                        <div class="dashboard-sections">
                            <div class="container">
                                <h2>My Notifications</h2>
                                <div class="error-message">
                                    Failed to load notifications. Please try again later.
                                </div>
                            </div>
                        </div>
                    `;
                }
                break;
        }
    } else if (user.role === 'admin') {
        switch (menuId) {
            // ... existing admin cases ...
        }
    } else if (user.role === 'researcher') {
        switch (menuId) {
            // ... existing researcher cases ...
        }
    }
}

// Initialize dashboard
document.addEventListener('DOMContentLoaded', async () => {
    // Check if user is logged in and token is valid
    const token = localStorage.getItem('token');
    if (!token || !checkTokenExpiration()) {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        window.location.href = '../landing/index.html';
        return;
    }

    // Load the Chat component first
    await loadChatComponent();

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

// Function to handle starting a chat
async function handleStartChat(inventionId) {
    try {
        // Get the token from localStorage
        const token = localStorage.getItem('token');
        if (!token) {
            throw new Error('You must be logged in to start a chat');
        }

        // Get the current user
        const currentUser = JSON.parse(localStorage.getItem('user'));
        if (!currentUser) {
            throw new Error('User information not found');
        }

        console.log('Starting chat for invention:', inventionId);

        // Create a new chat with just the invention ID
        const requestBody = {
            invention_id: inventionId
        };
        console.log('Request body:', requestBody);

        const createChatResponse = await fetch('https://127.0.0.1:5000/api/messages/start', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestBody),
            credentials: 'include'
        });

        if (!createChatResponse.ok) {
            const errorData = await createChatResponse.json();
            console.error('Chat creation error:', errorData);
            throw new Error(errorData.message || 'Failed to create chat');
        }

        const chatData = await createChatResponse.json();
        console.log('Created chat:', chatData);

        // Show success message and direct user to messages
        alert('Chat created successfully! Please go to the Messages section to start chatting.');
        
        // Optionally, you can automatically switch to the messages section
        const messagesLink = document.querySelector('a[data-menu="messages"]');
        if (messagesLink) {
            messagesLink.click();
        }

    } catch (error) {
        console.error('Error starting chat:', error);
        alert(error.message);
    }
}

async function loadMessagesContent() {
    const contentContainer = document.getElementById('dashboard-content');
    if (!contentContainer) return;

    try {
        // First, create the UI structure
        contentContainer.innerHTML = `
            <div class="messages-container">
                <div class="messages-sidebar">
                    <div class="messages-list" id="messages-list">
                        <div class="loading">Loading messages...</div>
                    </div>
                </div>
                <div class="messages-main">
                    <div class="chat-container" id="chat-container">
                        <div class="chat-placeholder">
                            Select a chat to start messaging
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Fetch existing chats
        const token = localStorage.getItem('token');
        if (!token) {
            throw new Error('You must be logged in to view messages');
        }

        const response = await fetch('https://127.0.0.1:5000/api/chats', {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Accept': 'application/json'
            },
            credentials: 'include'
        });

        if (!response.ok) {
            throw new Error('Failed to fetch chats');
        }

        const data = await response.json();
        const messagesList = document.getElementById('messages-list');
        
        if (data.chats && data.chats.length > 0) {
            messagesList.innerHTML = data.chats.map(chat => `
                <div class="chat-item" data-chat-id="${chat.id}" data-other-user-id="${chat.other_user_id}">
                    <h4>${chat.title}</h4>
                    <p>${chat.other_user_name} (${chat.other_user_role})</p>
                    <small>${chat.last_message_at ? new Date(chat.last_message_at).toLocaleString() : 'No messages yet'}</small>
                </div>
            `).join('');

            // Add click handlers to chat items
            document.querySelectorAll('.chat-item').forEach(item => {
                item.addEventListener('click', async () => {
                    const chatId = item.getAttribute('data-chat-id');
                    const otherUserId = item.getAttribute('data-other-user-id');
                    
                    console.log('Chat clicked:', { 
                        chatId, 
                        otherUserId,
                        dataset: item.dataset,
                        attributes: {
                            chatId: item.getAttribute('data-chat-id'),
                            otherUserId: item.getAttribute('data-other-user-id')
                        }
                    });
                    
                    if (!chatId || !otherUserId) {
                        console.error('Missing required chat data:', { chatId, otherUserId });
                        return;
                    }
                    
                    // Clear the placeholder and set up chat UI
                    const chatContainer = document.getElementById('chat-container');
                    chatContainer.innerHTML = `
                        <div class="chat-messages"></div>
                        <div class="chat-input">
                            <textarea placeholder="Type your message..." rows="3"></textarea>
                            <button class="send-button">Send</button>
                        </div>
                    `;
                    
                    // Initialize the chat only when a chat is selected
                    const chat = new Chat('chat-container');
                    await chat.initialize(chatId, otherUserId);
                });
            });
        } else {
            messagesList.innerHTML = '<div class="no-messages">No messages yet</div>';
        }

    } catch (error) {
        console.error('Error loading messages:', error);
        contentContainer.innerHTML = `
            <div class="error-message">
                Failed to load messages: ${error.message}
            </div>
        `;
    }
}

// Add this function to load the Chat component dynamically
async function loadChatComponent() {
    try {
        // Check if Chat is already defined
        if (typeof Chat !== 'undefined') {
            console.log('Chat component already loaded');
            return true;
        }

        const response = await fetch('/src/scripts/components/chat.js');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const text = await response.text();
        const script = document.createElement('script');
        script.type = 'text/javascript';
        script.textContent = text;
        document.head.appendChild(script);
        return true;
    } catch (error) {
        console.error('Error loading chat component:', error);
        return false;
    }
}

// Remove the standalone await call
// await loadChatComponent();

// Function to handle delete button click
function handleDeleteInvention(inventionId) {
    if (confirm('Are you sure you want to delete this invention? This action cannot be undone.')) {
        handlePasswordConfirmationModal(inventionId);
    }
}

// Function to handle access request response (accept/reject)
async function handleAccessRequestResponse(notificationId, action) {
    try {
        const token = localStorage.getItem('token');
        if (!token) {
            throw new Error('You must be logged in to respond to access requests');
        }

        // Get the notification element and its reference_id (which is the access_request_id)
        const notificationItem = document.querySelector(`.notification-item[data-notification-id="${notificationId}"]`);
        if (!notificationItem) {
            throw new Error('Notification not found');
        }
        const accessRequestId = notificationItem.dataset.referenceId;
        if (!accessRequestId) {
            throw new Error('Access request ID not found');
        }

        const response = await fetch(`https://127.0.0.1:5000/api/inventions/access-requests/${accessRequestId}/handle`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ action }),
            credentials: 'include'
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'An error occurred');
        }

        // Update the UI to reflect the new status
        const acceptBtn = notificationItem.querySelector('.accept-request-btn');
        const rejectBtn = notificationItem.querySelector('.reject-request-btn');
        const statusText = notificationItem.querySelector('.status-text') || document.createElement('span');
        statusText.className = 'status-text';

        if (action === 'accept') {
            acceptBtn.disabled = true;
            rejectBtn.disabled = false;
            statusText.style.color = '#28a745';
            statusText.textContent = 'Access request has been accepted';
        } else {
            acceptBtn.disabled = false;
            rejectBtn.disabled = true;
            statusText.style.color = '#dc3545';
            statusText.textContent = 'Access request has been rejected';
        }

        if (!notificationItem.querySelector('.status-text')) {
            notificationItem.querySelector('.notification-actions').appendChild(statusText);
        }
    } catch (error) {
        console.error(`Error ${action}ing access request:`, error);
        alert(error.message || `Failed to ${action} access request. Please try again.`);
    }
}

// Function to prompt for password
async function promptForPassword() {
    return new Promise((resolve, reject) => {
        const modal = document.createElement('div');
        modal.className = 'password-prompt-modal';
        modal.innerHTML = `
            <div class="password-prompt-content">
                <h3>Enter your password to start chat</h3>
                <p class="password-prompt-description">Your password is required to decrypt your private key for secure messaging.</p>
                <input type="password" id="chat-password" placeholder="Enter your password" autocomplete="current-password">
                <div class="password-prompt-buttons">
                    <button id="chat-password-cancel" class="cancel-btn">Cancel</button>
                    <button id="chat-password-submit" class="submit-btn">Submit</button>
                </div>
            </div>
        `;

        // Add styles with !important to override any other styles
        const style = document.createElement('style');
        style.textContent = `
            .password-prompt-modal {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.85);
                display: flex;
                justify-content: center;
                align-items: center;
                z-index: 1000;
                backdrop-filter: blur(5px);
            }
            .password-prompt-content {
                background: #121212;
                padding: 30px;
                border-radius: 12px;
                width: 400px;
                border: 1px solid rgb(136, 135, 135);
                box-shadow: 0 0 30px rgba(240, 234, 233, 0.4);
                animation: slideIn 0.3s ease-out;
                font-family: Poppins, sans-serif;
            }
            @keyframes slideIn {
                from {
                    transform: translateY(-30px);
                    opacity: 0;
                }
                to {
                    transform: translateY(0);
                    opacity: 1;
                }
            }
            .password-prompt-content h3 {
                margin: 0 0 10px 0;
                color: #ffffff;
                font-size: 1.5em;
                font-weight: 600;
            }
            .password-prompt-description {
                color: #b0b3c1;
                margin: 0 0 20px 0;
                font-size: 0.9em;
                line-height: 1.5;
            }
            .password-prompt-content input {
                width: 100%;
                padding: 12px;
                margin-bottom: 20px;
                border: 1px solid #ff4a2a !important;
                background-color: #1e1e1e;
                color: white;
                border-radius: 8px;
                font-size: 1em;
                box-sizing: border-box;
                transition: box-shadow 0.3s ease;
            }
            .password-prompt-content input:focus {
                outline: none !important;
                
            }
            .password-prompt-content input::placeholder {
                color: #6b7280;
            }
            .password-prompt-buttons {
                display: flex;
                justify-content: flex-end;
                gap: 12px;
            }
            .password-prompt-buttons button {
                padding: 10px 20px;
                border: none;
                border-radius: 8px;
                cursor: pointer;
                font-size: 0.9em;
                font-weight: 500;
                transition: all 0.2s;
                font-family: Poppins, sans-serif;
            }
            #chat-password-cancel {
                background: #2a2a2a;
                color: #e6e6ef;
                border: 1px solid #42434a;
            }
            #chat-password-cancel:hover {
                background: #333;
            }
            #chat-password-submit {
                background: #ff4a2a !important;
                color: white !important;
            }
            #chat-password-submit:hover {
                background: #e13a1a !important;
                transform: translateY(-1px);
                box-shadow: 0 2px 5px rgba(255, 74, 42, 0.4);
            }
            #chat-password-submit:active {
                transform: translateY(0);
                box-shadow: none;
            }
        `;
        document.head.appendChild(style);

        // Add event listeners
        const cancelBtn = modal.querySelector('#chat-password-cancel');
        const submitBtn = modal.querySelector('#chat-password-submit');
        const passwordInput = modal.querySelector('#chat-password');

        // Handle Enter key
        passwordInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                submitBtn.click();
            }
        });

        // Handle Escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                cancelBtn.click();
            }
        });

        cancelBtn.addEventListener('click', () => {
            document.body.removeChild(modal);
            document.head.removeChild(style);
            reject(new Error('Password prompt cancelled'));
        });

        submitBtn.addEventListener('click', () => {
            const password = passwordInput.value;
            if (!password) {
                passwordInput.style.borderColor = '#ff4444 !important';
                setTimeout(() => {
                    passwordInput.style.borderColor = '#ff4a2a !important';
                }, 2000);
                return;
            }
            document.body.removeChild(modal);
            document.head.removeChild(style);
            resolve(password);
        });

        // Add to DOM
        document.body.appendChild(modal);
        passwordInput.focus();
    });
}