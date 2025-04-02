-- Add invention_id column to notifications table
ALTER TABLE notifications
ADD COLUMN invention_id INTEGER REFERENCES inventions(id); 