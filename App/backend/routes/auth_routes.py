from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
import bcrypt
from datetime import datetime, timezone, timedelta
from models.user import User
from database import db
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import hashlib
import os
from base64 import b64encode
from dotenv import load_dotenv
from utils.audit_logger import log_security_event

# Load environment variables
load_dotenv()

# Get rate limiting configuration
MAX_LOGIN_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS', 5))
LOGIN_TIMEOUT_MINUTES = int(os.getenv('LOGIN_TIMEOUT_MINUTES', 15))

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Check if user already exists
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already registered'}), 400
    
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
        
        # Generate encryption keys for the user
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Get public key in PEM format
        public_key_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        # Encrypt private key with password hash
        key = hashlib.sha256(hashed_password).digest()
        iv = os.urandom(16)
        
        # Serialize private key
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Pad the data
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(private_key_bytes) + padder.finalize()
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine IV and encrypted data
        encrypted_private_key = b64encode(iv + encrypted_data).decode('utf-8')
        
        # Create user key entry
        from models.user_key import UserKey
        user_key = UserKey(
            user_id=new_user.id,
            public_key=public_key_pem,
            encrypted_private_key=encrypted_private_key
        )
        db.session.add(user_key)
        db.session.commit()
        
        return jsonify({'message': 'Registration successful'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Registration failed', 'error': str(e)}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    # Find user
    user = User.query.filter_by(email=data['email']).first()
    
    if not user:
        log_security_event(
            event_type='login_attempt',
            status='failure',
            details={'email': data['email'], 'reason': 'user_not_found'}
        )
        return jsonify({'message': 'Invalid email or password'}), 401
    
    # Check if account is locked
    if user.login_attempts >= MAX_LOGIN_ATTEMPTS and user.last_login_attempt:
        time_since_last_attempt = datetime.now(timezone.utc) - user.last_login_attempt
        if time_since_last_attempt < timedelta(minutes=LOGIN_TIMEOUT_MINUTES):
            remaining_time = LOGIN_TIMEOUT_MINUTES - (time_since_last_attempt.seconds // 60)
            log_security_event(
                event_type='account_lock',
                user_id=user.id,
                status='warning',
                details={'remaining_time': remaining_time}
            )
            return jsonify({
                'message': f'Too many login attempts. Account locked. Please try again in {remaining_time} minutes.'
            }), 429
        else:
            # Reset attempts if lockout period has expired
            user.login_attempts = 0
    
    # Verify password
    if not bcrypt.checkpw(data['password'].encode('utf-8'), user.password_hash.encode('utf-8')):
        # Update login attempt count
        user.login_attempts += 1
        user.last_login_attempt = datetime.now(timezone.utc)
        db.session.commit()
        
        log_security_event(
            event_type='login_attempt',
            user_id=user.id,
            status='failure',
            details={'attempts': user.login_attempts}
        )
        
        if user.login_attempts >= MAX_LOGIN_ATTEMPTS:
            log_security_event(
                event_type='account_lock',
                user_id=user.id,
                status='warning',
                details={'lockout_duration': LOGIN_TIMEOUT_MINUTES}
            )
            return jsonify({
                'message': f'Too many login attempts. Account locked for {LOGIN_TIMEOUT_MINUTES} minutes.'
            }), 429
        
        return jsonify({'message': 'Invalid email or password'}), 401
    
    # Reset login attempts on successful login
    user.login_attempts = 0
    user.last_login = datetime.now(timezone.utc)
    db.session.commit()
    
    # Log successful login
    log_security_event(
        event_type='login_attempt',
        user_id=user.id,
        status='success'
    )
    
    # Create access token with string user ID
    access_token = create_access_token(identity=str(user.id))
    
    return jsonify({
        'message': 'Login successful',
        'token': access_token,
        'user': user.to_dict()
    }), 200

@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    return jsonify(user.to_dict()), 200

@auth_bp.route('/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    data = request.get_json()
    
    # Update allowed fields
    if 'firstName' in data:
        user.first_name = data['firstName']
    if 'lastName' in data:
        user.last_name = data['lastName']
    if 'dateOfBirth' in data:
        try:
            user.date_of_birth = datetime.strptime(data['dateOfBirth'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'message': 'Invalid date format. Please use YYYY-MM-DD'}), 400
    
    try:
        db.session.commit()
        return jsonify({
            'message': 'Profile updated successfully',
            'user': user.to_dict()
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to update profile', 'error': str(e)}), 500

@auth_bp.route('/password-hash', methods=['POST'])
@jwt_required()
def get_password_hash():
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        password = data.get('password')
        
        if not password:
            return jsonify({'error': 'Password is required'}), 400
            
        user = User.query.get(current_user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        # Verify the password
        if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            return jsonify({'error': 'Invalid password'}), 401
            
        # Return the password hash
        return jsonify({'password_hash': user.password_hash}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500 