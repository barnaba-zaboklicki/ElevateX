from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timezone
from models.message import Message
from models.chat import Chat
from models.user import User
from models.invention import Invention
from models.chat_participant import ChatParticipant
from models.chat_key import ChatKey
from models.access_request import AccessRequest
from database import db
from utils.s3_utils import store_encrypted_message, get_message_from_s3
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

message_bp = Blueprint('message', __name__)

@message_bp.route('/chats', methods=['GET'])
@jwt_required()
def get_chats():
    """Get all chats for the current user."""
    current_user_id = int(get_jwt_identity())
    try:
        # Get all chats where the current user is a participant
        participant_chats = ChatParticipant.query.filter_by(user_id=current_user_id).all()
        chat_ids = [p.chat_id for p in participant_chats]
        
        if not chat_ids:
            return jsonify({'chats': []}), 200
        
        # Get the chats
        chats = Chat.query.filter(Chat.id.in_(chat_ids)).all()
        
        # Format the response
        formatted_chats = []
        for chat in chats:
            # Get the other participant
            other_participant = ChatParticipant.query.filter(
                ChatParticipant.chat_id == chat.id,
                ChatParticipant.user_id != current_user_id
            ).first()
            
            if not other_participant:
                continue
                
            other_user = User.query.get(other_participant.user_id)
            if not other_user:
                continue
                
            other_user_name = f"{other_user.first_name} {other_user.last_name}"
            
            # Get the last message
            last_message = Message.query.filter_by(chat_id=chat.id).order_by(Message.created_at.desc()).first()
            
            formatted_chats.append({
                'id': chat.id,
                'title': chat.title,
                'other_user_name': other_user_name,
                'other_user_role': other_participant.role,
                'last_message': '[Encrypted message]' if last_message else None,
                'last_message_at': last_message.created_at.isoformat() if last_message else None
            })
        
        return jsonify({'chats': formatted_chats}), 200
    except Exception as e:
        print(f"Error fetching chats: {str(e)}")
        return jsonify({
            'message': 'Failed to fetch chats',
            'error': str(e)
        }), 500

@message_bp.route('/start', methods=['POST'])
@jwt_required()
def start_chat():
    """Start a new chat."""
    current_user_id = int(get_jwt_identity())
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data provided'}), 400

        invention_id = data.get('invention_id')
        if not invention_id:
            return jsonify({'message': 'Invention ID is required'}), 400

        # Get the invention
        invention = Invention.query.get(invention_id)
        if not invention:
            return jsonify({'message': 'Invention not found'}), 404

        # Check if user is either the inventor or has an accepted access request
        if current_user_id != invention.inventor_id:
            access_request = AccessRequest.query.filter_by(
                invention_id=invention_id,
                investor_id=current_user_id,
                status='accepted'
            ).first()
            if not access_request:
                return jsonify({'message': 'Unauthorized'}), 403

        # Check if chat already exists
        existing_chat = Chat.query.filter_by(invention_id=invention_id).first()
        if existing_chat:
            return jsonify({
                'message': 'Chat already exists',
                'chat_id': existing_chat.id
            }), 200

        # Create new chat
        new_chat = Chat(
            invention_id=invention_id,
            title=f"Chat for {invention.title}"
        )
        db.session.add(new_chat)
        db.session.flush()  # Get the chat ID

        # Add participants
        inventor_participant = ChatParticipant(
            chat_id=new_chat.id,
            user_id=invention.inventor_id,
            role='inventor'
        )

        investor_participant = ChatParticipant(
            chat_id=new_chat.id,
            user_id=current_user_id,
            role='investor'
        )

        db.session.add(inventor_participant)
        db.session.add(investor_participant)
        db.session.commit()

        print(f"Successfully created chat {new_chat.id} for invention {invention_id}")

        return jsonify({
            'message': 'Chat started successfully',
            'chat_id': new_chat.id
        }), 201
    except Exception as e:
        print(f"Error in start_chat: {str(e)}")
        db.session.rollback()
        return jsonify({
            'message': 'Failed to start chat',
            'error': str(e)
        }), 500

@message_bp.route('/<int:chat_id>/messages', methods=['GET'])
@jwt_required()
def get_chat_messages(chat_id):
    """Get all messages for a specific chat."""
    current_user_id = int(get_jwt_identity())
    try:
        # Check if user is a participant in this chat
        participant = ChatParticipant.query.filter_by(
            chat_id=chat_id,
            user_id=current_user_id
        ).first()
        
        if not participant:
            return jsonify({'message': 'Unauthorized'}), 403
        
        # Get chat details
        chat = Chat.query.get(chat_id)
        if not chat:
            return jsonify({'message': 'Chat not found'}), 404
            
        # Get the other participant
        other_participant = ChatParticipant.query.filter(
            ChatParticipant.chat_id == chat_id,
            ChatParticipant.user_id != current_user_id
        ).first()
        
        if not other_participant:
            return jsonify({'message': 'Chat participant not found'}), 404
            
        other_user = User.query.get(other_participant.user_id)
        if not other_user:
            return jsonify({'message': 'User not found'}), 404
            
        # Get messages for this chat
        messages = Message.query.filter_by(chat_id=chat_id).order_by(Message.created_at).all()
        
        # Get encrypted content from S3 for each message
        formatted_messages = []
        for msg in messages:
            # Get encrypted content from S3
            encrypted_content = get_message_from_s3(msg.s3_key)
            if not encrypted_content['success']:
                print(f"Failed to get message {msg.id} from S3: {encrypted_content['error']}")
                continue
                
            sender = User.query.get(msg.sender_id)
            formatted_messages.append({
                'id': msg.id,
                'encrypted_content': encrypted_content['content'],
                'sender_id': msg.sender_id,
                'sender_name': f"{sender.first_name} {sender.last_name}",
                'created_at': msg.created_at.isoformat(),
                'is_sender': msg.sender_id == current_user_id
            })
        
        # Get invention_id from the chat's invention relationship
        invention_id = chat.invention.id if chat.invention else None
        
        return jsonify({
            'chat_id': chat_id,
            'invention_id': invention_id,
            'messages': formatted_messages
        }), 200
    except Exception as e:
        print(f"Error in get_chat_messages: {str(e)}")
        return jsonify({
            'message': 'Failed to fetch messages',
            'error': str(e)
        }), 500

@message_bp.route('/<int:chat_id>/send', methods=['POST'])
@jwt_required()
def send_message(chat_id):
    """Send a message in a chat."""
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
        encrypted_content = data.get('encrypted_content')
        
        if not encrypted_content:
            return jsonify({'message': 'Encrypted content is required'}), 400
        
        # First store in S3 to get the key
        s3_result = store_encrypted_message(chat_id, datetime.now(timezone.utc).timestamp(), encrypted_content)
        
        if not s3_result['success']:
            return jsonify({
                'message': 'Failed to store encrypted message',
                'error': s3_result['message']
            }), 500
        
        # Create new message with S3 key
        new_message = Message(
            chat_id=chat_id,
            sender_id=current_user_id,
            s3_key=s3_result['s3_key'],
            created_at=datetime.now(timezone.utc)
        )
        
        db.session.add(new_message)
        db.session.commit()
        
        # Get sender info for response
        sender = User.query.get(current_user_id)
        
        return jsonify({
            'message': {
                'id': new_message.id,
                'sender_id': current_user_id,
                'sender_name': f"{sender.first_name} {sender.last_name}",
                'created_at': new_message.created_at.isoformat(),
                's3_key': new_message.s3_key
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error in send_message: {str(e)}")
        return jsonify({
            'message': 'Failed to send message',
            'error': str(e)
        }), 500 