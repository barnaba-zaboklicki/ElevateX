from flask import Flask, request, jsonify, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from datetime import timedelta, datetime, timezone
import bcrypt
from dotenv import load_dotenv
import os
import re
from ssl_config import SSL_ENABLED, SSL_CERT_PATH, SSL_KEY_PATH, SECURITY_HEADERS

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configure app
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

# Rate limiting configuration
MAX_LOGIN_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS', 5))
LOGIN_TIMEOUT_MINUTES = int(os.getenv('LOGIN_TIMEOUT_MINUTES', 15))

# Password complexity requirements
PASSWORD_MIN_LENGTH = 8
PASSWORD_PATTERN = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)

# CORS configuration - simplified for development
CORS(app, 
     origins=["https://127.0.0.1:3000", "https://localhost:3000"],
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
     expose_headers=["Content-Type", "Authorization"]
)

# Add security headers to all responses
@app.after_request
def add_security_headers(response):
    # Add CORS headers explicitly
    origin = request.headers.get('Origin')
    if origin in ["https://127.0.0.1:3000", "https://localhost:3000"]:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
    
    # Add other security headers
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    return response

# Error handling
@app.errorhandler(Exception)
def handle_error(error):
    print(f"Error occurred: {str(error)}")
    return jsonify({
        'message': 'An error occurred',
        'error': str(error)
    }), 500

# User model
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # ENUM: 'admin', 'inventor', 'investor', 'researcher'
    date_of_birth = db.Column(db.Date, nullable=True)  # New column for DOB
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime(timezone=True))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    login_attempts = db.Column(db.Integer, default=0)
    last_login_attempt = db.Column(db.DateTime(timezone=True))

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'role': self.role,
            'date_of_birth': self.date_of_birth.isoformat() if self.date_of_birth else None,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

def validate_password(password):
    """Validate password complexity."""
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, "Password must be at least 8 characters long"
    
    if not PASSWORD_PATTERN.match(password):
        return False, "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character"
    
    return True, None

def check_rate_limit(user):
    """Check if user has exceeded login attempts."""
    if not user.last_login_attempt:
        return True
    
    # Reset attempts if timeout has passed
    timeout = timedelta(minutes=LOGIN_TIMEOUT_MINUTES)
    current_time = datetime.now(timezone.utc)
    if current_time - user.last_login_attempt > timeout:
        user.login_attempts = 0
        db.session.commit()
        return True
    
    return user.login_attempts < MAX_LOGIN_ATTEMPTS

# Create database tables
with app.app_context():
    try:
        print("Attempting to connect to database...")
        print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
        db.create_all()
        # Test query to verify connection
        users = User.query.all()
        print(f"Database connection successful. Found {len(users)} users in the database.")
        for user in users:
            print(f"User: {user.email}, Role: {user.role}")
    except Exception as e:
        print(f"Error connecting to database: {str(e)}")
        raise

# Routes
@app.route('/')
def root():
    # Get the host from the request
    host = request.headers.get('Host', '').split(':')[0]
    if host == '127.0.0.1':
        return redirect('https://127.0.0.1:3000')
    return redirect('https://localhost:3000')

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'message': 'API is running'}), 200

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Check if user already exists
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already registered'}), 400
    
    # Validate password
    is_valid, message = validate_password(data['password'])
    if not is_valid:
        return jsonify({'message': message}), 400
    
    # Hash password
    hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
    
    # Parse date of birth if provided
    date_of_birth = None
    if 'dateOfBirth' in data and data['dateOfBirth']:
        try:
            date_of_birth = datetime.strptime(data['dateOfBirth'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'message': 'Invalid date format. Please use YYYY-MM-DD'}), 400
    
    # Create new user
    new_user = User(
        first_name=data['firstName'],
        last_name=data['lastName'],
        email=data['email'],
        password_hash=hashed_password.decode('utf-8'),
        role=data['role'],
        date_of_birth=date_of_birth,
        login_attempts=0
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'Registration successful'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Registration failed'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    
    # Find user
    user = User.query.filter_by(email=data['email']).first()
    
    if not user:
        return jsonify({'message': 'Invalid email or password'}), 401
    
    # Check rate limit
    if not check_rate_limit(user):
        remaining_time = LOGIN_TIMEOUT_MINUTES - ((datetime.now(timezone.utc) - user.last_login_attempt).total_seconds() / 60)
        return jsonify({
            'message': f'Too many login attempts. Please try again in {int(remaining_time)} minutes'
        }), 429
    
    # Update login attempt count and timestamp
    user.login_attempts += 1
    user.last_login_attempt = datetime.now(timezone.utc)
    db.session.commit()
    
    # Verify password
    if not bcrypt.checkpw(data['password'].encode('utf-8'), user.password_hash.encode('utf-8')):
        return jsonify({'message': 'Invalid email or password'}), 401
    
    # Reset login attempts on successful login
    user.login_attempts = 0
    user.last_login = datetime.now(timezone.utc)
    db.session.commit()
    
    # Create access token
    access_token = create_access_token(identity=user.id)
    
    return jsonify({
        'message': 'Login successful',
        'token': access_token,
        'user': user.to_dict()
    }), 200

@app.route('/api/auth/profile', methods=['GET'])
@jwt_required()
def get_profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    return jsonify(user.to_dict()), 200

if __name__ == '__main__':
    try:
        print("Starting server with SSL...")
        app.run(debug=True, host='127.0.0.1', port=5000, ssl_context=(SSL_CERT_PATH, SSL_KEY_PATH))
    except Exception as e:
        print(f"Error starting server: {str(e)}")
        print("SSL configuration failed. Please check your certificates.")
        raise 