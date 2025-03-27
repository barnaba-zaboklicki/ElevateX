-- Add s3_key column to documents table
ALTER TABLE documents ADD COLUMN s3_key VARCHAR(1024) NOT NULL DEFAULT '';

-- Update existing records to use the file_path as s3_key
UPDATE documents SET s3_key = file_path WHERE s3_key = ''; 