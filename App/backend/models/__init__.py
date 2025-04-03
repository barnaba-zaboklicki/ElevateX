"""
Models package for the application.
This package contains all the database models used in the application.
"""

from .user import User
from .invention import Invention
from .document import Document
from .access_request import AccessRequest
from .notification import Notification
from .chat import Chat
from .message import Message
from .chat_participant import ChatParticipant
from .chat_key import ChatKey

# Import order matters - make sure models are imported in the correct order
# to avoid circular dependencies
__all__ = [
    'User',
    'Invention',
    'Document',
    'AccessRequest',
    'Notification',
    'Chat',
    'Message',
    'ChatParticipant',
    'ChatKey'
] 