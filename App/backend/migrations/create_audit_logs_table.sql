-- Create audit_logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    event_type VARCHAR(50) NOT NULL,
    user_id INTEGER REFERENCES users(id),
    ip_address VARCHAR(45),
    user_agent VARCHAR(255),
    details TEXT,
    status VARCHAR(20) NOT NULL
);

-- Create index on timestamp for faster queries
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);

-- Create index on event_type for filtering
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);

-- Create index on user_id for user-specific queries
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);

-- Create index on status for filtering
CREATE INDEX IF NOT EXISTS idx_audit_logs_status ON audit_logs(status); 