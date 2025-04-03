from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timezone
from models.message import Message
from models.chat import Chat
from models.user import User
from models.invention import Invention
from models.chat_participant import ChatParticipant
from database import db

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
            other_user_name = f"{other_user.first_name} {other_user.last_name}"
            
            # Get the last message
            last_message = Message.query.filter_by(chat_id=chat.id).order_by(Message.created_at.desc()).first()
            
            formatted_chats.append({
                'id': chat.id,
                'title': chat.title,
                'other_user_name': other_user_name,
                'other_user_role': other_participant.role,
                'last_message': last_message.content if last_message else None,
                'last_message_at': last_message.created_at.isoformat() if last_message else None
            })
        
        return jsonify({'chats': formatted_chats}), 200
    except Exception as e:
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
        invention_id = data.get('invention_id')
        
        if not invention_id:
            return jsonify({'message': 'Invention ID is required'}), 400
        
        # Get the invention
        invention = Invention.query.get(invention_id)
        if not invention:
            return jsonify({'message': 'Invention not found'}), 404
        
        # Check if user is the inventor or has accepted access
        current_user = User.query.get(current_user_id)
        if current_user.role == 'investor':
            # Check if investor has accepted access
            from models.access_request import AccessRequest
            access_request = AccessRequest.query.filter_by(
                invention_id=invention_id,
                investor_id=current_user_id,
                status='accepted'
            ).first()
            
            if not access_request:
                return jsonify({'message': 'You need accepted access to start a chat'}), 403
        
        # Check if chat already exists
        existing_chat = Chat.query.join(ChatParticipant).filter(
            ChatParticipant.user_id == current_user_id
        ).first()
        
        if existing_chat:
            return jsonify({
                'message': 'Chat already exists',
                'chat_id': existing_chat.id
            }), 200
        
        # Create new chat
        new_chat = Chat(
            title=f"Chat about {invention.title}",
            created_at=datetime.now(timezone.utc)
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
        
        return jsonify({
            'message': 'Chat started successfully',
            'chat_id': new_chat.id
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'message': 'Failed to start chat',
            'error': str(e)
        }), 500

@message_bp.route('/<int:chat_id>', methods=['GET'])
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
        
        # Get all messages for this chat
        messages = Message.query.filter_by(chat_id=chat_id).order_by(Message.created_at.asc()).all()
        
        # Format the response
        formatted_messages = []
        for message in messages:
            sender = User.query.get(message.sender_id)
            formatted_messages.append({
                'id': message.id,
                'content': message.content,
                'sender_id': message.sender_id,
                'sender_name': f"{sender.first_name} {sender.last_name}",
                'created_at': message.created_at.isoformat()
            })
        
        return jsonify({'messages': formatted_messages}), 200
    except Exception as e:
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
        content = data.get('content')
        
        if not content:
            return jsonify({'message': 'Message content is required'}), 400
        
        # Create new message
        new_message = Message(
            chat_id=chat_id,
            sender_id=current_user_id,
            content=content,
            encrypted_content=content,  # TODO: Implement proper encryption
            created_at=datetime.now(timezone.utc)
        )
        
        db.session.add(new_message)
        db.session.commit()
        
        return jsonify({
            'message': 'Message sent successfully',
            'message_id': new_message.id
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'message': 'Failed to send message',
            'error': str(e)
        }), 500 