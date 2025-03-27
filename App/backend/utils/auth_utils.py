from functools import wraps
from flask import request, jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from models.user import User

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            # Verify JWT token
            verify_jwt_in_request()
            
            # Get current user
            current_user_id = get_jwt_identity()
            current_user = User.query.get(current_user_id)
            
            if not current_user:
                return jsonify({'message': 'User not found'}), 404
            
            if not current_user.is_active:
                return jsonify({'message': 'User account is inactive'}), 403
            
            return f(current_user, *args, **kwargs)
        except Exception as e:
            return jsonify({'message': 'Invalid or missing token', 'error': str(e)}), 401
    
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            # Verify JWT token
            verify_jwt_in_request()
            
            # Get current user
            current_user_id = get_jwt_identity()
            current_user = User.query.get(current_user_id)
            
            if not current_user:
                return jsonify({'message': 'User not found'}), 404
            
            if not current_user.is_active:
                return jsonify({'message': 'User account is inactive'}), 403
            
            if current_user.role != 'admin':
                return jsonify({'message': 'Admin privileges required'}), 403
            
            return f(current_user, *args, **kwargs)
        except Exception as e:
            return jsonify({'message': 'Invalid or missing token', 'error': str(e)}), 401
    
    return decorated 