from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
import os
import uuid
from datetime import datetime
from utils.s3_utils import upload_file_to_s3, generate_presigned_url, delete_file_from_s3
from utils.auth_utils import token_required

file_bp = Blueprint('file', __name__)

ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'ppt', 'pptx', 'jpg', 'jpeg', 'png'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
MAX_TOTAL_SIZE = 50 * 1024 * 1024  # 50MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@file_bp.route('/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    """
    Upload a file to S3.
    Requires authentication.
    """
    if 'files' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    files = request.files.getlist('files')
    if not files or files[0].filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    # Check total size
    total_size = sum(len(file.read()) for file in files)
    for file in files:
        file.seek(0)  # Reset file pointers after reading
    
    if total_size > MAX_TOTAL_SIZE:
        return jsonify({'error': 'Total file size exceeds 50MB limit'}), 400
    
    uploaded_files = []
    for file in files:
        if not allowed_file(file.filename):
            return jsonify({'error': f'File type not allowed for {file.filename}'}), 400
        
        # Check individual file size
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > MAX_FILE_SIZE:
            return jsonify({'error': f'File {file.filename} exceeds 10MB limit'}), 400
        
        # Generate unique filename
        original_filename = secure_filename(file.filename)
        extension = original_filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{uuid.uuid4()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{extension}"
        
        # Upload to S3
        result = upload_file_to_s3(
            file,
            unique_filename,
            file.content_type
        )
        
        if result['success']:
            uploaded_files.append({
                'original_name': original_filename,
                'stored_name': unique_filename,
                'url': result['url']
            })
        else:
            # If any file fails, delete the previously uploaded files
            for uploaded_file in uploaded_files:
                delete_file_from_s3(uploaded_file['stored_name'])
            return jsonify({'error': f'Error uploading {file.filename}: {result["message"]}'}), 500
    
    return jsonify({
        'message': 'Files uploaded successfully',
        'files': uploaded_files
    }), 200

@file_bp.route('/files/<filename>', methods=['GET'])
@token_required
def get_file(current_user, filename):
    """
    Get a presigned URL for accessing a file.
    Requires authentication.
    """
    url = generate_presigned_url(filename)
    if url:
        return jsonify({
            'url': url
        }), 200
    return jsonify({'error': 'File not found'}), 404

@file_bp.route('/files/<filename>', methods=['DELETE'])
@token_required
def delete_file(current_user, filename):
    """
    Delete a file from S3.
    Requires authentication.
    """
    result = delete_file_from_s3(filename)
    if result['success']:
        return jsonify({
            'message': 'File deleted successfully'
        }), 200
    return jsonify({'error': result['message']}), 500 