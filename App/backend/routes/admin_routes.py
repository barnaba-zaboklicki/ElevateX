from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models.audit_log import AuditLog
from models.user import User
from database import db
from datetime import datetime, timedelta
import json

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/security-logs', methods=['GET'])
@jwt_required()
def get_security_logs():
    # Verify admin privileges
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    if not current_user or current_user.role != 'admin':
        return jsonify({'message': 'Admin privileges required'}), 403
    
    # Get query parameters
    event_type = request.args.get('event_type')
    status = request.args.get('status')
    user_id = request.args.get('user_id')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    # Build query
    query = AuditLog.query
    
    if event_type:
        query = query.filter(AuditLog.event_type == event_type)
    if status:
        query = query.filter(AuditLog.status == status)
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    if start_date:
        start = datetime.fromisoformat(start_date)
        query = query.filter(AuditLog.timestamp >= start)
    if end_date:
        end = datetime.fromisoformat(end_date)
        query = query.filter(AuditLog.timestamp <= end)
    
    # Get logs
    logs = query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    
    # Format response
    logs_data = [log.to_dict() for log in logs]
    
    return jsonify({
        'message': 'Security logs retrieved successfully',
        'logs': logs_data
    }), 200

@admin_bp.route('/security-stats', methods=['GET'])
@jwt_required()
def get_security_stats():
    # Verify admin privileges
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    if not current_user or current_user.role != 'admin':
        return jsonify({'message': 'Admin privileges required'}), 403
    
    # Get time range (default to last 24 hours)
    hours = int(request.args.get('hours', 24))
    start_time = datetime.now() - timedelta(hours=hours)
    
    # Get statistics
    failed_logins = AuditLog.query.filter(
        AuditLog.event_type == 'login_attempt',
        AuditLog.status == 'failure',
        AuditLog.timestamp >= start_time
    ).count()
    
    account_locks = AuditLog.query.filter(
        AuditLog.event_type == 'account_lock',
        AuditLog.timestamp >= start_time
    ).count()
    
    return jsonify({
        'message': 'Security statistics retrieved successfully',
        'stats': {
            'failed_logins': failed_logins,
            'account_locks': account_locks,
            'time_period': f'Last {hours} hours'
        }
    }), 200 