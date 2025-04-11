from flask import request
from models.audit_log import AuditLog
from database import db
import json

def log_security_event(event_type, user_id=None, status='success', details=None):
    """
    Log a security event to the audit log.
    
    Args:
        event_type (str): Type of event (e.g., 'login_attempt', 'account_lock')
        user_id (int, optional): ID of the user involved
        status (str): 'success', 'failure', or 'warning'
        details (dict, optional): Additional details about the event
    """
    try:
        # Get request information
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        
        # Create audit log entry
        log_entry = AuditLog(
            event_type=event_type,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=json.dumps(details) if details else None,
            status=status
        )
        
        # Save to database
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        # Log the error but don't break the application
        print(f"Error logging security event: {str(e)}")
        db.session.rollback() 