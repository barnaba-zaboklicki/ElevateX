from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from models.notification import Notification
from models.access_request import AccessRequest
from database import db
from flask import current_app
import traceback
from sqlalchemy import text

notification_bp = Blueprint('notification', __name__)

@notification_bp.route('/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    """Get all notifications for the current user."""
    try:
        # Log request headers
        print("Request headers:", dict(request.headers))
        
        # Get and log user ID
        current_user_id = get_jwt_identity()
        print(f"Current user ID from JWT: {current_user_id}")
        
        if not current_user_id:
            print("No user ID found in JWT token")
            return jsonify({
                'message': 'User not authenticated',
                'error': 'No user ID found in token'
            }), 401
        
        # Test database connection
        try:
            result = db.session.execute(text('SELECT 1'))
            print("Database connection successful")
        except Exception as db_error:
            print(f"Database connection error: {str(db_error)}")
            print(f"Database error traceback: {traceback.format_exc()}")
            raise
        
        # Check if notifications table exists
        try:
            table_exists = db.session.execute(text("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'notifications')")).scalar()
            print(f"Notifications table exists: {table_exists}")
        except Exception as table_error:
            print(f"Error checking notifications table: {str(table_error)}")
            print(f"Table check traceback: {traceback.format_exc()}")
            raise
        
        # Get all notifications for the current user
        try:
            notifications = Notification.query.filter_by(
                user_id=current_user_id
            ).order_by(Notification.created_at.desc()).all()
            print(f"Found {len(notifications)} notifications for user {current_user_id}")
        except Exception as query_error:
            print(f"Query error: {str(query_error)}")
            print(f"Query traceback: {traceback.format_exc()}")
            raise
        
        # Convert to dictionary format
        notifications_data = []
        for notification in notifications:
            try:
                notification_dict = {
                    'id': notification.id,
                    'title': notification.title,
                    'message': notification.message,
                    'type': notification.type,
                    'reference_id': notification.reference_id,
                    'is_read': notification.is_read,
                    'created_at': notification.created_at.isoformat() if notification.created_at else None
                }

                # If this is an access request notification, get the status
                if notification.type == 'access_request' and notification.reference_id:
                    access_request = AccessRequest.query.get(notification.reference_id)
                    if access_request:
                        notification_dict['status'] = access_request.status
                        print(f"Added status {access_request.status} for notification {notification.id}")

                notifications_data.append(notification_dict)
                print(f"Processed notification {notification.id}")
            except Exception as process_error:
                print(f"Error processing notification {notification.id}: {str(process_error)}")
                print(f"Process error traceback: {traceback.format_exc()}")
                continue
        
        print(f"Successfully processed {len(notifications_data)} notifications")
        return jsonify({
            'notifications': notifications_data
        }), 200
        
    except Exception as e:
        print(f"Error in get_notifications: {str(e)}")
        print(f"Error type: {type(e)}")
        print(f"Full traceback: {traceback.format_exc()}")
        current_app.logger.error(f"Error fetching notifications: {str(e)}")
        current_app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({
            'message': 'Failed to fetch notifications',
            'error': str(e)
        }), 500 