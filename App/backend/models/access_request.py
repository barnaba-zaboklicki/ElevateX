from datetime import datetime
from database import db

class AccessRequest(db.Model):
    __tablename__ = 'access_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    invention_id = db.Column(db.Integer, db.ForeignKey('inventions.id'), nullable=False)
    investor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, accepted, rejected
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=True, onupdate=datetime.utcnow)
    
    # Relationships
    invention = db.relationship('Invention', backref=db.backref('access_requests', lazy=True))
    investor = db.relationship('User', backref=db.backref('access_requests', lazy=True))
    
    def to_dict(self):
        return {
            'id': self.id,
            'invention_id': self.invention_id,
            'investor_id': self.investor_id,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        } 