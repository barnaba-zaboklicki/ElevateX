from flask import Flask, request, jsonify, redirect, make_response
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from datetime import timedelta
from dotenv import load_dotenv
import os
from ssl_config import SSL_ENABLED, SSL_CERT_PATH, SSL_KEY_PATH, SECURITY_HEADERS
from routes.auth_routes import auth_bp
from routes.invention_routes import invention_bp
from routes.file_routes import file_bp
from routes.notification_routes import notification_bp
from routes.message_routes import message_bp
from routes.key_routes import key_bp
from database import db
from models import User, Invention, Document, AccessRequest, Notification, Chat, Message, ChatParticipant, ChatKey

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

# Initialize extensions
db.init_app(app)
jwt = JWTManager(app)

# Configure CORS
CORS(app, 
     origins=["https://127.0.0.1:3000", "https://localhost:3000", "http://127.0.0.1:3000", "http://localhost:3000"],
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization", "X-Requested-With", "Accept"],
     expose_headers=["Content-Type", "Authorization"],
     allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     max_age=3600
)

# Add security headers to all responses
@app.after_request
def add_security_headers(response):
    # Add CORS headers explicitly
    origin = request.headers.get('Origin')
    if origin in ["https://127.0.0.1:3000", "https://localhost:3000", "http://127.0.0.1:3000", "http://localhost:3000"]:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With, Accept'
        response.headers['Access-Control-Max-Age'] = '3600'
    
    # Add other security headers
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    return response

# Handle OPTIONS requests for all routes
@app.before_request
def handle_options():
    if request.method == 'OPTIONS':
        response = make_response()
        origin = request.headers.get('Origin')
        if origin in ["https://127.0.0.1:3000", "https://localhost:3000", "http://127.0.0.1:3000", "http://localhost:3000"]:
            response.headers.add('Access-Control-Allow-Origin', origin)
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept')
            response.headers.add('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            response.headers.add('Access-Control-Max-Age', '3600')
        return response

# Error handling
@app.errorhandler(Exception)
def handle_error(error):
    print(f"Error occurred: {str(error)}")
    return jsonify({
        'message': 'An error occurred',
        'error': str(error)
    }), 500

# Routes
@app.route('/', methods=['GET', 'OPTIONS'])
def root():
    if request.method == 'OPTIONS':
        return '', 204
        
    # Get the host from the request
    host = request.headers.get('Host', '').split(':')[0]
    if host == '127.0.0.1':
        return redirect('https://127.0.0.1:3000')
    return redirect('https://localhost:3000')

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'message': 'API is running'}), 200

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(invention_bp, url_prefix='/api/inventions')
app.register_blueprint(file_bp, url_prefix='/api/files')
app.register_blueprint(notification_bp, url_prefix='/api/notification')
app.register_blueprint(message_bp, url_prefix='/api/messages')
app.register_blueprint(key_bp, url_prefix='/api/keys')

# Create database tables
with app.app_context():
    try:
        print("Attempting to connect to database...")
        print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
        db.create_all()
        print("Database connection successful.")
    except Exception as e:
        print(f"Error connecting to database: {str(e)}")
        raise

if __name__ == '__main__':
    try:
        if SSL_ENABLED:
            app.run(
                host='127.0.0.1',
                port=5000,
                ssl_context=(SSL_CERT_PATH, SSL_KEY_PATH),
                debug=True
            )
        else:
            app.run(
                host='127.0.0.1',
                port=5000,
                debug=True
            )
    except Exception as e:
        print(f"Error starting the server: {str(e)}") 