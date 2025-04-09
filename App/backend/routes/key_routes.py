from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models.user import User
from models.user_key import UserKey
from database import db
from datetime import datetime, timezone
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

key_bp = Blueprint('key', __name__)

@key_bp.route('/user/me', methods=['GET'])
@jwt_required()
def get_current_user_keys():
    try:
        current_user_id = get_jwt_identity()
        logger.debug(f"Fetching keys for user ID: {current_user_id}")
        
        user = User.query.get(current_user_id)
        if not user:
            logger.error(f"User not found with ID: {current_user_id}")
            return jsonify({'error': 'User not found'}), 404

        user_key = UserKey.query.filter_by(user_id=current_user_id).first()
        if not user_key:
            logger.error(f"User keys not found for user ID: {current_user_id}")
            return jsonify({'error': 'User keys not found'}), 404

        logger.debug(f"Successfully retrieved keys for user ID: {current_user_id}")
        return jsonify({
            'public_key': user_key.public_key,
            'encrypted_private_key': user_key.encrypted_private_key
        }), 200

    except Exception as e:
        logger.error(f"Error fetching user keys: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@key_bp.route('/user/<int:user_id>/public', methods=['GET'])
@jwt_required()
def get_user_public_key(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        user_key = UserKey.query.filter_by(user_id=user_id).first()
        if not user_key:
            return jsonify({'error': 'User keys not found'}), 404

        return jsonify({
            'public_key': user_key.public_key
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@key_bp.route('/user/upload', methods=['POST'])
@jwt_required()
def upload_user_keys():
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()

        if not data or 'public_key' not in data or 'encrypted_private_key' not in data:
            return jsonify({'error': 'Missing required fields'}), 400

        user_key = UserKey.query.filter_by(user_id=current_user_id).first()
        if user_key:
            user_key.public_key = data['public_key']
            user_key.encrypted_private_key = data['encrypted_private_key']
            user_key.updated_at = datetime.now(timezone.utc)
        else:
            user_key = UserKey(
                user_id=current_user_id,
                public_key=data['public_key'],
                encrypted_private_key=data['encrypted_private_key']
            )
            db.session.add(user_key)

        db.session.commit()
        return jsonify({'message': 'Keys uploaded successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500 