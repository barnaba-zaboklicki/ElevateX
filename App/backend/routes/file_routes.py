from flask import Blueprint, request, jsonify, send_file
from werkzeug.utils import secure_filename
import os
import uuid
from datetime import datetime
from utils.s3_utils import upload_file_to_s3, generate_presigned_url, delete_file_from_s3, get_file_from_s3
from utils.auth_utils import token_required
from utils.audit_logger import log_security_event
import urllib.parse
import io

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
        log_security_event(
            event_type='document_upload',
            user_id=current_user.id,
            status='failure',
            details={'reason': 'no_file_part'}
        )
        return jsonify({'error': 'No file part'}), 400
    
    files = request.files.getlist('files')
    if not files or files[0].filename == '':
        log_security_event(
            event_type='document_upload',
            user_id=current_user.id,
            status='failure',
            details={'reason': 'no_selected_file'}
        )
        return jsonify({'error': 'No selected file'}), 400
    
    # Check total size
    total_size = sum(len(file.read()) for file in files)
    for file in files:
        file.seek(0)  # Reset file pointers after reading
    
    if total_size > MAX_TOTAL_SIZE:
        log_security_event(
            event_type='document_upload',
            user_id=current_user.id,
            status='failure',
            details={
                'reason': 'total_size_exceeded',
                'size': total_size,
                'limit': MAX_TOTAL_SIZE
            }
        )
        return jsonify({'error': 'Total file size exceeds 50MB limit'}), 400
    
    uploaded_files = []
    for file in files:
        if not allowed_file(file.filename):
            log_security_event(
                event_type='document_upload',
                user_id=current_user.id,
                status='failure',
                details={
                    'filename': file.filename,
                    'reason': 'file_type_not_allowed'
                }
            )
            return jsonify({'error': f'File type not allowed for {file.filename}'}), 400
        
        # Check individual file size
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > MAX_FILE_SIZE:
            log_security_event(
                event_type='document_upload',
                user_id=current_user.id,
                status='failure',
                details={
                    'filename': file.filename,
                    'size': file_size,
                    'limit': MAX_FILE_SIZE,
                    'reason': 'file_size_exceeded'
                }
            )
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
            # Log successful upload
            log_security_event(
                event_type='document_upload',
                user_id=current_user.id,
                status='success',
                details={
                    'document_name': original_filename,
                    'document_type': file.content_type,
                    'invention_id': unique_filename.split('/')[1] if len(unique_filename.split('/')) > 1 else 'N/A',
                    'size': file_size
                }
            )
        else:
            # If any file fails, delete the previously uploaded files
            for uploaded_file in uploaded_files:
                delete_file_from_s3(uploaded_file['stored_name'])
            # Log upload failure
            log_security_event(
                event_type='document_upload',
                user_id=current_user.id,
                status='failure',
                details={
                    'filename': original_filename,
                    'reason': result['message']
                }
            )
            return jsonify({'error': f'Error uploading {file.filename}: {result["message"]}'}), 500
    
    return jsonify({
        'message': 'Files uploaded successfully',
        'files': uploaded_files
    }), 200

@file_bp.route('/files/<path:filename>', methods=['GET'])
@token_required
def get_file(current_user, filename):
    """
    Stream a file directly from S3.
    Requires authentication.
    """
    try:
        print("\n=== File Request Debug Logs ===")
        print(f"Request headers: {dict(request.headers)}")
        print(f"Received request for file: {filename}")
        print(f"Current user: {current_user.id}")
        
        # Decode the URL-encoded filename
        decoded_filename = urllib.parse.unquote(filename)
        print(f"Decoded filename: {decoded_filename}")
        
        # Handle s3:// prefix if present
        if decoded_filename.startswith('s3://'):
            # Remove the s3:// prefix and bucket name
            decoded_filename = decoded_filename.replace('s3://elevatex-inventions/', '')
            print(f"Removed s3:// prefix. New filename: {decoded_filename}")
        
        # Get the file from S3
        print(f"Attempting to get file from S3 with key: {decoded_filename}")
        file_data = get_file_from_s3(decoded_filename)
        
        if not file_data:
            print("File not found in S3 or file is empty")
            # Log failed access attempt
            log_security_event(
                event_type='document_access',
                user_id=current_user.id,
                status='failure',
                details={'filename': filename, 'reason': 'file_not_found'}
            )
            return jsonify({'error': 'File not found or is empty'}), 404
            
        print("Successfully retrieved file from S3")
            
        # Create a file-like object from the bytes
        file_obj = file_data['Body']  # Already a BytesIO object from get_file_from_s3
        
        # Get the content type from the file data
        content_type = file_data['ContentType']
        print(f"Content type: {content_type}")
        
        # Get the original filename from the S3 key
        original_filename = decoded_filename.split('/')[-1]
        print(f"Original filename: {original_filename}")
        
        # Log successful access
        log_security_event(
            event_type='document_access',
            user_id=current_user.id,
            status='success',
            details={
                'document_name': original_filename,
                'document_type': content_type,
                'invention_id': decoded_filename.split('/')[1] if len(decoded_filename.split('/')) > 1 else 'N/A'
            }
        )
        
        # Stream the file to the client
        print("Streaming file to client...")
        response = send_file(
            file_obj,
            mimetype=content_type,
            as_attachment=False,
            download_name=original_filename
        )
        print("File streamed successfully")
        print("=== End File Request Debug Logs ===\n")
        return response
        
    except Exception as e:
        print("\n=== File Request Error Logs ===")
        print(f"Error streaming file: {str(e)}")
        print(f"Error type: {type(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        print("=== End File Request Error Logs ===\n")
        
        # Log error
        log_security_event(
            event_type='document_access',
            user_id=current_user.id,
            status='failure',
            details={
                'filename': filename,
                'reason': str(e),
                'error_type': type(e).__name__
            }
        )
        return jsonify({'error': str(e)}), 500

@file_bp.route('/files/<filename>', methods=['DELETE'])
@token_required
def delete_file(current_user, filename):
    """
    Delete a file from S3.
    Requires authentication.
    """
    try:
        result = delete_file_from_s3(filename)
        if result['success']:
            # Log successful deletion
            log_security_event(
                event_type='document_delete',
                user_id=current_user.id,
                status='success',
                details={
                    'document_name': filename.split('/')[-1],
                    'invention_id': filename.split('/')[1] if len(filename.split('/')) > 1 else 'N/A'
                }
            )
            return jsonify({
                'message': 'File deleted successfully'
            }), 200
        
        # Log failed deletion
        log_security_event(
            event_type='document_delete',
            user_id=current_user.id,
            status='failure',
            details={
                'filename': filename,
                'reason': result['message']
            }
        )
        return jsonify({'error': result['message']}), 500
    except Exception as e:
        # Log error during deletion
        log_security_event(
            event_type='document_delete',
            user_id=current_user.id,
            status='failure',
            details={
                'filename': filename,
                'reason': str(e),
                'error_type': type(e).__name__
            }
        )
        return jsonify({'error': str(e)}), 500 