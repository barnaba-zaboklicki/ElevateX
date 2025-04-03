from database import db
from datetime import datetime, timezone

class Message(db.Model):
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chats.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    encrypted_content = db.Column(db.Text, nullable=False)
    s3_key = db.Column(db.String(255))  # Store the S3 key for the encrypted message
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    sender = db.relationship('models.user.User', backref=db.backref('messages', lazy=True))
    
    def to_dict(self):
        return {
            'id': self.id,
            'chat_id': self.chat_id,
            'sender_id': self.sender_id,
            'content': self.content,
            'encrypted_content': self.encrypted_content,
            's3_key': self.s3_key,
            'created_at': self.created_at.isoformat()
        } 