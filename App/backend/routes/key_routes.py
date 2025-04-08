from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models.chat_key import ChatKey
from models.chat_participant import ChatParticipant
from database import db
from datetime import datetime, timezone

key_bp = Blueprint('key', __name__)

@key_bp.route('/<int:chat_id>/upload', methods=['POST'])
@jwt_required()
def upload_key_bundle(chat_id):
    """Upload a Signal Protocol key bundle for a chat participant."""
    current_user_id = int(get_jwt_identity())
    try:
        # Check if user is a participant in this chat
        participant = ChatParticipant.query.filter_by(
            chat_id=chat_id,
            user_id=current_user_id
        ).first()
        
        if not participant:
            return jsonify({'message': 'Unauthorized'}), 403

        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data provided'}), 400

        required_fields = ['registration_id', 'identity_key', 'signed_pre_key', 'signature', 'one_time_pre_keys']
        for field in required_fields:
            if field not in data:
                return jsonify({'message': f'Missing required field: {field}'}), 400

        # Update or create key bundle
        chat_key = ChatKey.query.filter_by(chat_id=chat_id, user_id=current_user_id).first()
        if not chat_key:
            chat_key = ChatKey(
                chat_id=chat_id,
                user_id=current_user_id
            )
            db.session.add(chat_key)

        # Update key bundle
        chat_key.registration_id = data['registration_id']
        chat_key.identity_public_key = data['identity_key']
        chat_key.signed_pre_public_key = data['signed_pre_key']
        chat_key.signature = data['signature']
        chat_key.one_time_pre_keys = data['one_time_pre_keys']
        chat_key.updated_at = datetime.now(timezone.utc)

        db.session.commit()

        return jsonify({
            'message': 'Key bundle uploaded successfully'
        }), 200

    except Exception as e:
        db.session.rollback()
        print(f"Error uploading key bundle: {str(e)}")
        return jsonify({
            'message': 'Failed to upload key bundle',
            'error': str(e)
        }), 500

@key_bp.route('/<int:user_id>/bundle', methods=['GET'])
@jwt_required()
def get_key_bundle(user_id):
    """Get a user's Signal Protocol key bundle."""
    current_user_id = int(get_jwt_identity())
    try:
        # Get the chat key for the requested user
        chat_key = ChatKey.query.filter_by(user_id=user_id).first()
        
        if not chat_key:
            return jsonify({'message': 'Key bundle not found'}), 404

        # Get a one-time pre-key (and remove it from the available keys)
        one_time_pre_key = None
        if chat_key.one_time_pre_keys and len(chat_key.one_time_pre_keys) > 0:
            one_time_pre_key = chat_key.one_time_pre_keys.pop(0)
            chat_key.updated_at = datetime.now(timezone.utc)
            db.session.commit()

        return jsonify({
            'registration_id': chat_key.registration_id,
            'identity_key': chat_key.identity_public_key,
            'signed_pre_key': chat_key.signed_pre_public_key,
            'signature': chat_key.signature,
            'one_time_pre_key': one_time_pre_key
        }), 200

    except Exception as e:
        print(f"Error fetching key bundle: {str(e)}")
        return jsonify({
            'message': 'Failed to fetch key bundle',
            'error': str(e)
        }), 500 