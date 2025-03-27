from datetime import datetime, timezone
from database import db
from sqlalchemy import Enum

class Invention(db.Model):
    __tablename__ = 'inventions'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    technical_details = db.Column(db.Text)
    patent_status = db.Column(db.String(20), nullable=False, default='not_filed')  # not_filed, in_progress, granted, rejected
    funding_status = db.Column(db.String(20), nullable=False, default='not_requested')  # not_requested, requested, approved, rejected
    status = db.Column(Enum('draft', 'pending', 'approved', 'rejected', name='invention_status'), nullable=False, default='draft')
    inventor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'technical_details': self.technical_details,
            'patent_status': self.patent_status,
            'funding_status': self.funding_status,
            'status': self.status,
            'inventor_id': self.inventor_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        } 