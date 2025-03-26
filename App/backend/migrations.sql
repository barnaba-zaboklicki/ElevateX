-- Add login attempt tracking columns
ALTER TABLE users
ADD COLUMN login_attempts INTEGER DEFAULT 0,
ADD COLUMN last_login_attempt TIMESTAMP WITH TIME ZONE; 