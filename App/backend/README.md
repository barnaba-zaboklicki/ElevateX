# Backend API Documentation

## Overview
This is the backend API for the ElevateX application, handling user authentication and profile management.

## Setup

1. Create a virtual environment:
```bash
python -m venv venv
```

2. Activate the virtual environment:
- Windows:
```bash
venv\Scripts\activate
```
- Unix/MacOS:
```bash
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
- Copy `.env.example` to `.env`
- Update the secret keys in `.env`

5. Initialize the database:
```bash
flask db init
flask db migrate
flask db upgrade
```

## Running the Application

Start the development server:
```bash
python app.py
```

The server will start at `http://localhost:5000`

## API Endpoints

### Authentication

#### Register
- **URL**: `/api/auth/register`
- **Method**: `POST`
- **Body**:
```json
{
    "firstName": "string",
    "lastName": "string",
    "email": "string",
    "password": "string",
    "role": "string"
}
```
- **Response**: 201 Created or 400 Bad Request

#### Login
- **URL**: `/api/auth/login`
- **Method**: `POST`
- **Body**:
```json
{
    "email": "string",
    "password": "string"
}
```
- **Response**: 200 OK with token or 401 Unauthorized

#### Get Profile
- **URL**: `/api/auth/profile`
- **Method**: `GET`
- **Headers**: `Authorization: Bearer <token>`
- **Response**: 200 OK with user data or 404 Not Found

## Database Schema

### User
- `id`: Integer (Primary Key)
- `first_name`: String (50)
- `last_name`: String (50)
- `email`: String (120, Unique)
- `password`: String (60)
- `role`: String (20)

## Security
- Passwords are hashed using bcrypt
- JWT tokens are used for authentication
- CORS is enabled for frontend access
- Environment variables for sensitive data

## Error Handling
- 400: Bad Request (Invalid input)
- 401: Unauthorized (Invalid credentials)
- 404: Not Found (Resource not found)
- 500: Internal Server Error

## Development
- Flask debug mode is enabled
- SQLAlchemy for database operations
- Flask-JWT-Extended for authentication
- Flask-CORS for cross-origin requests 