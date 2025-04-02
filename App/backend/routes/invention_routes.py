from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timezone
from models.invention import Invention
from models.document import Document
from database import db
from utils.s3_utils import upload_file_to_s3, delete_file_from_s3
import os
from models.user import User
from models.access_request import AccessRequest
from models.notification import Notification
from flask import current_app

invention_bp = Blueprint('invention', __name__)

@invention_bp.route('/', methods=['POST'])
@jwt_required()
def create_invention():
    """Create a new invention."""
    current_user_id = int(get_jwt_identity())  # Convert string ID to integer
    
    # Debug logging
    print("Received request data:")
    print("Form data:", request.form)
    print("Files:", request.files)
    
    # Get form data
    title = request.form.get('title')
    description = request.form.get('description')
    technical_details = request.form.get('technical_details')
    patent_status = request.form.get('patent_status', 'not_filed')
    funding_status = request.form.get('funding_status', 'not_requested')
    
    # Debug logging
    print("Parsed form data:")
    print("Title:", title)
    print("Description:", description)
    print("Technical details:", technical_details)
    print("Patent status:", patent_status)
    print("Funding status:", funding_status)
    print("User ID:", current_user_id)
    
    if not all([title, description, technical_details]):
        print("Missing required fields")
        return jsonify({
            'message': 'Missing required fields',
            'error': 'Title, description, and technical details are required'
        }), 422
    
    # Create new invention
    new_invention = Invention(
        title=title,
        description=description,
        technical_details=technical_details,
        patent_status=patent_status,
        funding_status=funding_status,
        inventor_id=current_user_id,
        status='draft',
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc)
    )
    
    try:
        db.session.add(new_invention)
        db.session.commit()
        
        # Handle file uploads if any
        files = request.files.getlist('attachments')
        if files:
            # Create upload directory if it doesn't exist
            upload_dir = os.path.join('uploads', str(new_invention.id))
            os.makedirs(upload_dir, exist_ok=True)
            
            # Save each file and create document entries
            for file in files:
                if file.filename:
                    # Save file locally temporarily
                    file_path = os.path.join(upload_dir, file.filename)
                    file.save(file_path)
                    
                    # Upload to S3
                    s3_result = upload_file_to_s3(
                        file_obj=file,
                        filename=f"inventions/{new_invention.id}/{file.filename}",
                        content_type=file.content_type
                    )
                    
                    if not s3_result['success']:
                        raise Exception(f"Failed to upload file to S3: {s3_result['message']}")
                    
                    # Create document entry
                    document = Document(
                        invention_id=new_invention.id,
                        filename=file.filename,
                        file_path=s3_result['url'],
                        s3_key=s3_result['s3_key'],  # Store the S3 key
                        file_type=file.content_type,
                        file_size=os.path.getsize(file_path),
                        uploaded_by=current_user_id,
                        created_at=datetime.now(timezone.utc)
                    )
                    db.session.add(document)
                    
                    # Clean up local file
                    os.remove(file_path)
            
            # Commit document entries
            db.session.commit()
        
        return jsonify({
            'message': 'Invention created successfully',
            'invention': new_invention.to_dict()
        }), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error creating invention: {str(e)}")  # Debug log
        return jsonify({
            'message': 'Failed to create invention',
            'error': str(e)
        }), 500

@invention_bp.route('/', methods=['GET'])
@jwt_required()
def get_inventions():
    """Get all inventions for the current user."""
    current_user_id = get_jwt_identity()
    try:
        inventions = Invention.query.filter_by(inventor_id=current_user_id).all()
        return jsonify({
            'inventions': [invention.to_dict() for invention in inventions]
        }), 200
    except Exception as e:
        return jsonify({
            'message': 'Failed to fetch inventions',
            'error': str(e)
        }), 500

@invention_bp.route('/<int:invention_id>', methods=['GET'])
@jwt_required()
def get_invention(invention_id):
    """Get a specific invention."""
    current_user_id = int(get_jwt_identity())  # Convert string ID to integer
    try:
        invention = Invention.query.get(invention_id)
        
        if not invention:
            return jsonify({'message': 'Invention not found'}), 404
        
        # Get current user's role
        current_user = User.query.get(current_user_id)
        if not current_user:
            return jsonify({'message': 'User not found'}), 404
        
        # Allow access if:
        # 1. User is the inventor
        # 2. User is an investor and the invention is not in draft status
        if invention.inventor_id != current_user_id:
            if current_user.role != 'investor' or invention.status == 'draft':
                return jsonify({'message': 'Unauthorized'}), 403
        
        return jsonify(invention.to_dict()), 200
    except Exception as e:
        return jsonify({
            'message': 'Failed to fetch invention',
            'error': str(e)
        }), 500

@invention_bp.route('/<int:invention_id>', methods=['PUT'])
@jwt_required()
def update_invention(invention_id):
    """Update a specific invention."""
    current_user_id = get_jwt_identity()
    try:
        invention = Invention.query.get(invention_id)
        
        if not invention:
            return jsonify({'message': 'Invention not found'}), 404
        
        # Check if user has permission to update this invention
        if invention.inventor_id != current_user_id:
            return jsonify({'message': 'Unauthorized'}), 403
        
        data = request.get_json()
        
        # Update fields
        if 'title' in data:
            invention.title = data['title']
        if 'description' in data:
            invention.description = data['description']
        if 'technical_details' in data:
            invention.technical_details = data['technical_details']
        if 'patent_status' in data:
            invention.patent_status = data['patent_status']
        if 'funding_status' in data:
            invention.funding_status = data['funding_status']
        
        invention.updated_at = datetime.now(timezone.utc)
        
        db.session.commit()
        return jsonify({
            'message': 'Invention updated successfully',
            'invention': invention.to_dict()
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'message': 'Failed to update invention',
            'error': str(e)
        }), 500

@invention_bp.route('/<int:invention_id>', methods=['DELETE'])
@jwt_required()
def delete_invention(invention_id):
    """Delete a specific invention."""
    current_user_id = int(get_jwt_identity())  # Convert string ID to integer
    try:
        invention = Invention.query.get(invention_id)
        
        if not invention:
            return jsonify({'message': 'Invention not found'}), 404
        
        # Check if user has permission to delete this invention
        if invention.inventor_id != current_user_id:
            return jsonify({'message': 'Unauthorized'}), 403
        
        # Get password from request body
        data = request.get_json()
        password = data.get('password')
        
        if not password:
            return jsonify({'message': 'Password is required'}), 400
        
        # Get user and verify password
        user = User.query.get(current_user_id)
        if not user or not user.verify_password(password):
            return jsonify({'message': 'Invalid password'}), 401
        
        # Delete associated documents from S3 if any
        documents = Document.query.filter_by(invention_id=invention_id).all()
        print(f"Found {len(documents)} documents to delete")  # Debug log
        
        for document in documents:
            try:
                print(f"Attempting to delete document: {document.filename}")  # Debug log
                print(f"S3 key: {document.s3_key}")  # Debug log
                
                # Delete from S3 using the stored key
                s3_result = delete_file_from_s3(document.s3_key)
                if not s3_result['success']:
                    print(f"Warning: Failed to delete file from S3: {s3_result['message']}")
                    # Continue with deletion even if S3 deletion fails
                
                # Delete document record
                db.session.delete(document)
            except Exception as e:
                print(f"Warning: Error deleting document: {str(e)}")
                # Continue with deletion even if document deletion fails
        
        # Delete the invention
        db.session.delete(invention)
        db.session.commit()
        
        return jsonify({
            'message': 'Invention deleted successfully'
        }), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting invention: {str(e)}")  # Debug log
        return jsonify({
            'message': 'Failed to delete invention',
            'error': str(e)
        }), 500

@invention_bp.route('/available', methods=['GET'])
@jwt_required()
def get_available_projects():
    """Get all available projects for investors."""
    try:
        current_user_id = get_jwt_identity()
        # Get all projects that are not in draft status
        inventions = Invention.query.filter(
            Invention.status != 'draft'
        ).all()
        
        # Convert to dictionary and include only necessary fields for initial view
        projects = []
        for invention in inventions:
            # Check if current user has a pending request
            has_pending_request = False
            if current_user_id:
                pending_request = AccessRequest.query.filter_by(
                    invention_id=invention.id,
                    investor_id=current_user_id,
                    status='pending'
                ).first()
                has_pending_request = pending_request is not None
            
            projects.append({
                'id': invention.id,
                'title': invention.title,
                'description': invention.description,
                'patent_status': invention.patent_status,
                'funding_status': invention.funding_status,
                'status': invention.status,
                'created_at': invention.created_at.isoformat() if invention.created_at else None,
                'has_pending_request': has_pending_request
            })
        
        return jsonify({
            'projects': projects
        }), 200
    except Exception as e:
        return jsonify({
            'message': 'Failed to fetch available projects',
            'error': str(e)
        }), 500

@invention_bp.route('/<int:invention_id>/status', methods=['PUT'])
@jwt_required()
def update_invention_status(invention_id):
    """Update the status of an invention."""
    current_user_id = int(get_jwt_identity())  # Convert string ID to integer
    try:
        invention = Invention.query.get(invention_id)
        
        if not invention:
            return jsonify({'message': 'Invention not found'}), 404
        
        # Debug logging
        print(f"Current user ID: {current_user_id}, Invention inventor ID: {invention.inventor_id}")
        
        # Check if user has permission to update this invention
        if invention.inventor_id != current_user_id:
            return jsonify({'message': 'Unauthorized'}), 403
        
        data = request.get_json()
        new_status = data.get('status')
        
        if not new_status or new_status not in ['draft', 'pending', 'approved', 'rejected']:
            return jsonify({
                'message': 'Invalid status',
                'error': 'Status must be one of: draft, pending, approved, rejected'
            }), 400
        
        invention.status = new_status
        invention.updated_at = datetime.now(timezone.utc)
        
        db.session.commit()
        return jsonify({
            'message': 'Invention status updated successfully',
            'invention': invention.to_dict()
        }), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error updating invention status: {str(e)}")  # Debug log
        return jsonify({
            'message': 'Failed to update invention status',
            'error': str(e)
        }), 500

@invention_bp.route('/<int:invention_id>/request-access', methods=['POST'])
@jwt_required()
def request_access(invention_id):
    try:
        current_user_id = get_jwt_identity()
        print(f"Processing access request for invention {invention_id} by user {current_user_id}")
        
        # Get the invention
        invention = Invention.query.get_or_404(invention_id)
        print(f"Found invention: {invention.title}")
        
        # Check if user is an investor
        user = User.query.get(current_user_id)
        print(f"User role: {user.role if user else 'None'}")
        
        if not user or user.role != 'investor':
            print("User is not an investor")
            return jsonify({'error': 'Only investors can request access'}), 403
            
        # Check if request already exists
        existing_request = AccessRequest.query.filter_by(
            invention_id=invention_id,
            investor_id=current_user_id,
            status='pending'
        ).first()
        
        if existing_request:
            print("Access request already exists")
            return jsonify({'error': 'Access request already pending'}), 400
            
        # Create new access request
        new_request = AccessRequest(
            invention_id=invention_id,
            investor_id=current_user_id,
            status='pending',
            created_at=datetime.utcnow()
        )
        
        db.session.add(new_request)
        db.session.commit()
        print("Created new access request")
        
        # Create notification for the inventor
        notification = Notification(
            user_id=invention.inventor_id,
            title='New Access Request',
            message=f'Investor {user.first_name} {user.last_name} has requested access to your invention "{invention.title}"',
            type='access_request',
            reference_id=new_request.id,
            created_at=datetime.utcnow()
        )
        
        db.session.add(notification)
        db.session.commit()
        print("Created notification for inventor")
        
        return jsonify({
            'message': 'Access request sent successfully',
            'request_id': new_request.id
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error requesting access: {str(e)}")
        current_app.logger.error(f"Error requesting access: {str(e)}")
        return jsonify({'error': 'Failed to process access request'}), 500

@invention_bp.route('/access-requests/<int:request_id>/handle', methods=['POST'])
@jwt_required()
def handle_access_request(request_id):
    try:
        current_user_id = int(get_jwt_identity())  # Convert string ID to integer
        print(f"Current user ID: {current_user_id}")
        
        data = request.get_json()
        print(f"Request data: {data}")
        
        if not data or 'action' not in data:
            return jsonify({'error': 'Missing required fields'}), 400
            
        action = data['action']
        
        if action not in ['accept', 'reject']:
            return jsonify({'error': 'Invalid action'}), 400
            
        # Get the access request
        access_request = AccessRequest.query.get_or_404(request_id)
        print(f"Access request: {access_request.to_dict()}")
        
        # Get the invention to verify ownership
        invention = Invention.query.get_or_404(access_request.invention_id)
        print(f"Invention: {invention.to_dict()}")
        
        # Verify the current user is the invention owner
        print(f"Checking ownership: current_user_id={current_user_id}, invention.inventor_id={invention.inventor_id}")
        if invention.inventor_id != current_user_id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        # Update request status
        access_request.status = 'accepted' if action == 'accept' else 'rejected'
        access_request.updated_at = datetime.utcnow()
        
        if action == 'accept':
            # Create notification for the investor
            notification = Notification(
                user_id=access_request.investor_id,
                title='Access Request Accepted',
                message=f'Your request to access "{invention.title}" has been accepted',
                type='access_request_accepted',
                reference_id=invention.id,
                created_at=datetime.utcnow()
            )
            db.session.add(notification)
        else:  # action == 'reject'
            # Create notification for the investor
            notification = Notification(
                user_id=access_request.investor_id,
                title='Access Request Rejected',
                message=f'Your request to access "{invention.title}" has been rejected',
                type='access_request_rejected',
                reference_id=invention.id,
                created_at=datetime.utcnow()
            )
            db.session.add(notification)
        
        db.session.commit()
        
        return jsonify({
            'message': f'Access request {action}ed successfully',
            'status': access_request.status
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error handling access request: {str(e)}")
        return jsonify({'error': 'Failed to process access request'}), 500

@invention_bp.route('/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    """Get all notifications for the current user."""
    try:
        current_user_id = get_jwt_identity()
        print(f"Fetching notifications for user {current_user_id}")
        
        # Get all notifications for the current user
        notifications = Notification.query.filter_by(
            user_id=current_user_id
        ).order_by(Notification.created_at.desc()).all()
        
        # Convert to dictionary format
        notifications_data = [{
            'id': notification.id,
            'title': notification.title,
            'message': notification.message,
            'type': notification.type,
            'reference_id': notification.reference_id,
            'is_read': notification.is_read,
            'created_at': notification.created_at.isoformat() if notification.created_at else None
        } for notification in notifications]
        
        print(f"Found {len(notifications_data)} notifications")
        return jsonify({
            'notifications': notifications_data
        }), 200
        
    except Exception as e:
        print(f"Error fetching notifications: {str(e)}")
        current_app.logger.error(f"Error fetching notifications: {str(e)}")
        return jsonify({
            'message': 'Failed to fetch notifications',
            'error': str(e)
        }), 500

@invention_bp.route('/access-requests/<int:request_id>', methods=['GET'])
@jwt_required()
def get_access_request(request_id):
    """Get details of a specific access request."""
    try:
        current_user_id = get_jwt_identity()
        
        # Get the access request
        access_request = AccessRequest.query.get_or_404(request_id)
        
        # Get the invention
        invention = Invention.query.get_or_404(access_request.invention_id)
        
        # Verify the current user is either the inventor or the investor
        if invention.inventor_id != current_user_id and access_request.investor_id != current_user_id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        return jsonify({
            'id': access_request.id,
            'invention_id': access_request.invention_id,
            'investor_id': access_request.investor_id,
            'status': access_request.status,
            'created_at': access_request.created_at.isoformat() if access_request.created_at else None,
            'updated_at': access_request.updated_at.isoformat() if access_request.updated_at else None
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error fetching access request: {str(e)}")
        return jsonify({'error': 'Failed to fetch access request'}), 500 