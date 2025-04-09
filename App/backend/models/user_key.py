from database import db
from datetime import datetime, timezone

class UserKey(db.Model):
    __tablename__ = 'user_encryption_keys'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    encrypted_private_key = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    user = db.relationship('User', backref=db.backref('key', uselist=False))

    def __init__(self, user_id, public_key, encrypted_private_key):
        self.user_id = user_id
        self.public_key = public_key
        self.encrypted_private_key = encrypted_private_key

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'public_key': self.public_key,
            'encrypted_private_key': self.encrypted_private_key,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        } 