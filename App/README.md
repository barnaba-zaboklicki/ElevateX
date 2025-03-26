# Innovation Hub Platform

A comprehensive platform connecting inventors, investors, and researchers to foster innovation and collaboration.

## Project Structure

```
.
├── frontend/                 # Frontend application
│   ├── public/              # Static files served directly
│   │   ├── graphics/        # Images, icons, etc.
│   │   └── assets/         # Other static assets
│   └── src/                # Source files
│       ├── components/     # Reusable UI components
│       │   ├── common/     # Shared components
│       │   └── auth/       # Authentication components
│       ├── pages/         # HTML pages
│       │   ├── landing/   # Landing page
│       │   └── dashboard/ # Dashboard pages
│       │       ├── admin/
│       │       ├── inventor/
│       │       ├── investor/
│       │       └── researcher/
│       ├── scripts/       # JavaScript files
│       │   ├── common/    # Shared scripts
│       │   └── pages/     # Page-specific scripts
│       ├── styles/        # CSS files
│       │   ├── common/    # Shared styles
│       │   └── pages/     # Page-specific styles
│       ├── services/      # API services
│       └── utils/         # Utility functions
│
├── backend/                # Backend application
│   ├── src/
│   │   ├── config/       # Configuration files
│   │   ├── controllers/  # Route controllers
│   │   ├── middleware/   # Custom middleware
│   │   ├── models/       # Data models
│   │   ├── routes/       # API routes
│   │   ├── services/     # Business logic
│   │   ├── types/        # TypeScript types
│   │   └── utils/        # Utility functions
│   └── tests/            # Test files
│       ├── unit/         # Unit tests
│       └── integration/  # Integration tests
│
├── database/              # Database related files
│   ├── migrations/       # Database migrations
│   ├── seeds/           # Seed data
│   └── schemas/         # Database schemas
│
├── docs/                 # Documentation
│   ├── api/             # API documentation
│   ├── security/        # Security documentation
│   └── setup/           # Setup guides
│
└── docker/              # Docker configuration
    ├── frontend/        # Frontend container config
    └── backend/         # Backend container config
```

## Features

- **Multi-User Platform**: Support for different user roles (Admin, Inventor, Investor, Researcher)
- **Secure Authentication**: Role-based access control and secure user authentication
- **Dashboard Interface**: Customized dashboards for each user role
- **API Integration**: RESTful API for frontend-backend communication
- **Database Management**: Structured database with migrations and seed data
- **Docker Support**: Containerized deployment configuration

## Getting Started

### Prerequisites

- Node.js (v14 or higher)
- PostgreSQL
- Docker (optional)

### Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd [project-directory]
```

2. Install dependencies:
```bash
# Frontend
cd frontend
npm install

# Backend
cd ../backend
npm install
```

3. Set up environment variables:
```bash
# Create .env files in both frontend and backend directories
cp .env.example .env
```

4. Start the development servers:
```bash
# Frontend (from frontend directory)
npm run dev

# Backend (from backend directory)
npm run dev
```

### Docker Deployment

To run the application using Docker:

```bash
docker-compose up --build
```

## Development

### Frontend Development

- Located in the `frontend` directory
- Uses vanilla JavaScript and CSS
- Organized by feature and component
- Common styles and scripts shared across pages

### Backend Development

- Located in the `backend` directory
- Node.js/Express.js server
- RESTful API architecture
- Modular structure with separate concerns

### Database Management

- Migrations located in `database/migrations`
- Seed data in `database/seeds`
- Schema definitions in `database/schemas`

## Testing

```bash
# Run backend tests
cd backend
npm test

# Run frontend tests
cd frontend
npm test
```

## Documentation

- API documentation: `docs/api`
- Security guidelines: `docs/security`
- Setup instructions: `docs/setup`

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 