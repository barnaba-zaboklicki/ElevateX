from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timezone
from models.invention import Invention
from database import db
from utils.auth_utils import token_required

invention_bp = Blueprint('invention', __name__)

@invention_bp.route('/', methods=['POST'])
@token_required
def create_invention(current_user):
    """Create a new invention."""
    data = request.get_json()
    
    # Create new invention
    new_invention = Invention(
        title=data['title'],
        description=data['description'],
        technical_details=data.get('technical_details'),
        patent_status=data.get('patent_status', 'not_filed'),
        funding_status=data.get('funding_status', 'not_requested'),
        inventor_id=current_user.id,
        status='draft',
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc)
    )
    
    try:
        db.session.add(new_invention)
        db.session.commit()
        return jsonify({
            'message': 'Invention created successfully',
            'invention': new_invention.to_dict()
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'message': 'Failed to create invention',
            'error': str(e)
        }), 500

@invention_bp.route('/', methods=['GET'])
@token_required
def get_inventions(current_user):
    """Get all inventions for the current user."""
    try:
        if current_user.role == 'admin':
            # Admins can see all inventions
            inventions = Invention.query.all()
        else:
            # Other users can only see their own inventions
            inventions = Invention.query.filter_by(inventor_id=current_user.id).all()
        
        return jsonify({
            'inventions': [invention.to_dict() for invention in inventions]
        }), 200
    except Exception as e:
        return jsonify({
            'message': 'Failed to fetch inventions',
            'error': str(e)
        }), 500

@invention_bp.route('/<int:invention_id>', methods=['GET'])
@token_required
def get_invention(current_user, invention_id):
    """Get a specific invention."""
    try:
        invention = Invention.query.get(invention_id)
        
        if not invention:
            return jsonify({'message': 'Invention not found'}), 404
        
        # Check if user has permission to view this invention
        if current_user.role != 'admin' and invention.inventor_id != current_user.id:
            return jsonify({'message': 'Unauthorized'}), 403
        
        return jsonify(invention.to_dict()), 200
    except Exception as e:
        return jsonify({
            'message': 'Failed to fetch invention',
            'error': str(e)
        }), 500

@invention_bp.route('/<int:invention_id>', methods=['PUT'])
@token_required
def update_invention(current_user, invention_id):
    """Update a specific invention."""
    try:
        invention = Invention.query.get(invention_id)
        
        if not invention:
            return jsonify({'message': 'Invention not found'}), 404
        
        # Check if user has permission to update this invention
        if current_user.role != 'admin' and invention.inventor_id != current_user.id:
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
        if 'status' in data and current_user.role == 'admin':
            invention.status = data['status']
        
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
@token_required
def delete_invention(current_user, invention_id):
    """Delete a specific invention."""
    try:
        invention = Invention.query.get(invention_id)
        
        if not invention:
            return jsonify({'message': 'Invention not found'}), 404
        
        # Check if user has permission to delete this invention
        if current_user.role != 'admin' and invention.inventor_id != current_user.id:
            return jsonify({'message': 'Unauthorized'}), 403
        
        db.session.delete(invention)
        db.session.commit()
        
        return jsonify({
            'message': 'Invention deleted successfully'
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'message': 'Failed to delete invention',
            'error': str(e)
        }), 500 