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
    
    contentDiv.innerHTML = `
        <div class="welcome-section">
            <h1>Welcome, ${firstName}!</h1>
            <h2>${roleConfigs[role].title}</h2>
        </div>
        <div class="dashboard-sections">
            <!-- Existing content will be preserved -->
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
}

// Initialize dashboard
function initDashboard() {
    const role = getUserRole();
    if (!role) {
        window.location.href = '../auth/login.html';
        return;
    }

    loadRoleSpecificMenu(role);
    loadDashboardContent(role);

    // Add event listener for logout
    document.getElementById('logoutBtn').addEventListener('click', (e) => {
        e.preventDefault();
        localStorage.removeItem('user');
        localStorage.removeItem('token');
        window.location.href = '../landing/index.html';
    });

    // Add event listeners for menu items
    document.querySelectorAll('[data-menu]').forEach(menuItem => {
        menuItem.addEventListener('click', (e) => {
            e.preventDefault();
            const menuId = menuItem.getAttribute('data-menu');
            // Handle menu item clicks (to be implemented)
            console.log(`Menu item clicked: ${menuId}`);
        });
    });
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', initDashboard); 