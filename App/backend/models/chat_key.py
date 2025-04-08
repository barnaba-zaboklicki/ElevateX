from database import db
from datetime import datetime, timezone
from sqlalchemy.dialects.postgresql import ARRAY

class ChatKey(db.Model):
    __tablename__ = 'chat_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chats.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    registration_id = db.Column(db.Integer)
    identity_public_key = db.Column(db.Text)
    signed_pre_public_key = db.Column(db.Text)
    signature = db.Column(db.Text)
    one_time_pre_keys = db.Column(ARRAY(db.Text))
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    user = db.relationship('models.user.User', backref=db.backref('chat_keys', lazy=True))
    
    def __init__(self, chat_id, user_id, registration_id=None, identity_public_key=None,
                 signed_pre_public_key=None, signature=None, one_time_pre_keys=None):
        self.chat_id = chat_id
        self.user_id = user_id
        self.registration_id = registration_id
        self.identity_public_key = identity_public_key
        self.signed_pre_public_key = signed_pre_public_key
        self.signature = signature
        self.one_time_pre_keys = one_time_pre_keys or []

    def to_dict(self):
        return {
            'id': self.id,
            'chat_id': self.chat_id,
            'user_id': self.user_id,
            'registration_id': self.registration_id,
            'identity_public_key': self.identity_public_key,
            'signed_pre_public_key': self.signed_pre_public_key,
            'signature': self.signature,
            'one_time_pre_keys': self.one_time_pre_keys,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        } 