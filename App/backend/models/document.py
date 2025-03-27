from datetime import datetime, timezone
from database import db

class Document(db.Model):
    __tablename__ = 'documents'
    
    id = db.Column(db.Integer, primary_key=True)
    invention_id = db.Column(db.Integer, db.ForeignKey('inventions.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(1024), nullable=False)  # S3 URL
    s3_key = db.Column(db.String(1024), nullable=False)  # S3 key for deletion
    file_type = db.Column(db.String(100), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)  # Size in bytes
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    def to_dict(self):
        return {
            'id': self.id,
            'invention_id': self.invention_id,
            'filename': self.filename,
            'file_path': self.file_path,
            's3_key': self.s3_key,
            'file_type': self.file_type,
            'file_size': self.file_size,
            'uploaded_by': self.uploaded_by,
            'created_at': self.created_at.isoformat() if self.created_at else None
        } 