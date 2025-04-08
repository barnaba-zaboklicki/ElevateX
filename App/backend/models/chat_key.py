from database import db
from datetime import datetime, timezone

class ChatKey(db.Model):
    __tablename__ = 'chat_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chats.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    identity_public_key = db.Column(db.Text, nullable=False)
    signed_pre_public_key = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    user = db.relationship('models.user.User', backref=db.backref('chat_keys', lazy=True))
    
    def to_dict(self):
        return {
            'id': self.id,
            'chat_id': self.chat_id,
            'user_id': self.user_id,
            'identity_public_key': self.identity_public_key,
            'signed_pre_public_key': self.signed_pre_public_key,
            'created_at': self.created_at.isoformat()
        } 