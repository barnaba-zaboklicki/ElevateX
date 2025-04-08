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
from utils.s3_utils import store_encrypted_message

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
                'last_message': last_message.content if last_message else None,
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
        invention_id = data.get('invention_id')
        title = data.get('title')
        identity_public_key = data.get('public_key')  # Frontend still sends as public_key
        signed_pre_public_key = data.get('private_key')  # Frontend still sends as private_key
        
        print(f"Starting chat for invention {invention_id} by user {current_user_id}")
        
        if not invention_id:
            print("Error: Missing invention_id")
            return jsonify({'message': 'Invention ID is required'}), 400
        
        # Get the invention
        invention = Invention.query.get(invention_id)
        if not invention:
            print(f"Error: Invention {invention_id} not found")
            return jsonify({'message': 'Invention not found'}), 404
        
        # Check if user is the inventor or has accepted access
        current_user = User.query.get(current_user_id)
        if current_user.role == 'investor':
            # Check if investor has accepted access
            access_request = AccessRequest.query.filter_by(
                invention_id=invention_id,
                investor_id=current_user_id,
                status='accepted'
            ).first()
            
            if not access_request:
                return jsonify({'message': 'You need accepted access to start a chat'}), 403
        
        # Check if chat already exists
        existing_chat = Chat.query.join(ChatParticipant).filter(
            ChatParticipant.user_id == current_user_id,
            ChatParticipant.chat_id == Chat.id,
            Chat.id.in_(
                db.session.query(ChatParticipant.chat_id).filter(
                    ChatParticipant.user_id == invention.inventor_id
                )
            )
        ).first()
        
        if existing_chat:
            return jsonify({
                'message': 'Chat already exists',
                'chat_id': existing_chat.id
            }), 200
        
        # Create new chat
        new_chat = Chat(
            title=title or f"Chat about {invention.title}",
            invention_id=invention_id,
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
        
        # Store encryption keys for both participants
        if identity_public_key and signed_pre_public_key:
            # Validate key format
            try:
                # Attempt to decode base64 keys
                import base64
                base64.b64decode(identity_public_key)
                base64.b64decode(signed_pre_public_key)
            except Exception as e:
                return jsonify({
                    'message': 'Invalid key format',
                    'error': 'Keys must be base64 encoded'
                }), 400
                
            # Store keys for inventor
            inventor_key = ChatKey(
                chat_id=new_chat.id,
                user_id=invention.inventor_id,
                identity_public_key=identity_public_key,
                signed_pre_public_key=signed_pre_public_key
            )
            
            # Store keys for investor
            investor_key = ChatKey(
                chat_id=new_chat.id,
                user_id=current_user_id,
                identity_public_key=identity_public_key,
                signed_pre_public_key=signed_pre_public_key
            )
            
            db.session.add(inventor_key)
            db.session.add(investor_key)
        
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
            
        # Get the other user's public key from ChatKey
        other_user_key = ChatKey.query.filter_by(
            chat_id=chat_id,
            user_id=other_participant.user_id
        ).first()
        
        if not other_user_key:
            return jsonify({'message': 'Chat key not found'}), 404
        
        # Get messages for this chat
        messages = Message.query.filter_by(chat_id=chat_id).order_by(Message.created_at).all()
        
        # Format messages with sender info
        formatted_messages = []
        for msg in messages:
            sender = User.query.get(msg.sender_id)
            formatted_messages.append({
                'id': msg.id,
                'content': msg.content,
                'encrypted_content': msg.encrypted_content,
                's3_key': msg.s3_key,
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
            'other_user': {
                'id': other_user.id,
                'name': f"{other_user.first_name} {other_user.last_name}",
                'public_key': other_user_key.identity_public_key
            },
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
        content = data.get('content')
        encrypted_content = data.get('encrypted_content')
        
        print(f"Received message - Content: {content}, Encrypted: {encrypted_content[:50]}...")  # Log first 50 chars
        
        if not content or not encrypted_content:
            return jsonify({'message': 'Message content and encrypted content are required'}), 400
        
        # Create new message
        new_message = Message(
            chat_id=chat_id,
            sender_id=current_user_id,
            content=content,
            encrypted_content=encrypted_content,
            created_at=datetime.now(timezone.utc)
        )
        
        db.session.add(new_message)
        db.session.flush()  # Get the message ID
        
        print(f"Created message with ID: {new_message.id}")  # Log message ID
        
        # Store encrypted message in S3
        print("Attempting to store message in S3...")  # Log S3 attempt
        s3_result = store_encrypted_message(chat_id, new_message.id, encrypted_content)
        print(f"S3 result: {s3_result}")  # Log S3 result
        
        if not s3_result['success']:
            db.session.rollback()
            return jsonify({
                'message': 'Failed to store encrypted message',
                'error': s3_result['message']
            }), 500
        
        # Update message with S3 key
        new_message.s3_key = s3_result['s3_key']
        db.session.commit()
        
        # Get sender info for response
        sender = User.query.get(current_user_id)
        
        return jsonify({
            'message': {
                'id': new_message.id,
                'content': content,
                'sender_id': current_user_id,
                'sender_name': f"{sender.first_name} {sender.last_name}",
                'created_at': new_message.created_at.isoformat()
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error in send_message: {str(e)}")  # Log the full error
        return jsonify({
            'message': 'Failed to send message',
            'error': str(e)
        }), 500 