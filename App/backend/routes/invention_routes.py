from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timezone
from models.invention import Invention
from models.document import Document
from database import db
from utils.s3_utils import upload_file_to_s3, delete_file_from_s3
import os
from models.user import User

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
        # Get all projects that are not in draft status
        inventions = Invention.query.filter(
            Invention.status != 'draft'
        ).all()
        
        # Convert to dictionary and include only necessary fields for initial view
        projects = [{
            'id': invention.id,
            'title': invention.title,
            'description': invention.description,
            'patent_status': invention.patent_status,
            'funding_status': invention.funding_status,
            'status': invention.status,
            'created_at': invention.created_at.isoformat() if invention.created_at else None
        } for invention in inventions]
        
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