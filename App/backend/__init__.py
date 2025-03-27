from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from database import db
from routes.auth_routes import auth_bp
from routes.invention_routes import invention_bp
from routes.user_routes import user_bp
from routes.notification_routes import notification_bp
import os

def create_app():
    app = Flask(__name__)
    CORS(app, supports_credentials=True)
    
    # Configure JWT
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your-secret-key')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600  # 1 hour
    jwt = JWTManager(app)
    
    # Configure database
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/elevatex')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(invention_bp, url_prefix='/api/inventions')
    app.register_blueprint(user_bp, url_prefix='/api/users')
    app.register_blueprint(notification_bp, url_prefix='/api/notification')
    
    return app 