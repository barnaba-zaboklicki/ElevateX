from datetime import datetime, timezone
from database import db

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    event_type = db.Column(db.String(50), nullable=False)  # e.g., 'login_attempt', 'account_lock', 'document_access'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 compatible
    user_agent = db.Column(db.String(255), nullable=True)
    details = db.Column(db.Text, nullable=True)  # JSON string of additional details
    status = db.Column(db.String(20), nullable=False)  # 'success', 'failure', 'warning'
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'event_type': self.event_type,
            'user_id': self.user_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'details': self.details,
            'status': self.status
        } 
 