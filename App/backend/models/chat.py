from database import db
from datetime import datetime, timezone

class Chat(db.Model):
    __tablename__ = 'chats'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    invention_id = db.Column(db.Integer, db.ForeignKey('inventions.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # Relationships
    invention = db.relationship('models.invention.Invention', backref=db.backref('chats', lazy=True))
    participants = db.relationship('models.chat_participant.ChatParticipant', backref='chat', lazy=True, cascade="all, delete-orphan")
    chat_messages = db.relationship('models.message.Message', backref='chat', lazy=True, cascade="all, delete-orphan")
    keys = db.relationship('models.chat_key.ChatKey', backref='chat', lazy=True, cascade="all, delete-orphan")
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'invention_id': self.invention_id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        } 