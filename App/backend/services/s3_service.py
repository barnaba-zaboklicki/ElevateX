import boto3
import os
from botocore.exceptions import ClientError
from werkzeug.utils import secure_filename
from config.s3_config import (
    AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY,
    AWS_REGION,
    S3_BUCKET_NAME,
    INVENTIONS_FOLDER,
    TEMP_FOLDER,
    ALLOWED_EXTENSIONS,
    URL_EXPIRATION
)

class S3Service:
    def __init__(self):
        self.s3_client = boto3.client(
            's3',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_REGION
        )

    def upload_file(self, file, invention_id, document_id):
        """
        Upload a file to S3 and return the file path
        """
        try:
            # Secure the filename
            filename = secure_filename(file.filename)
            
            # Create the S3 path
            s3_path = f"{INVENTIONS_FOLDER}/{invention_id}/documents/{document_id}_{filename}"
            
            # Upload the file
            self.s3_client.upload_fileobj(
                file,
                S3_BUCKET_NAME,
                s3_path,
                ExtraArgs={
                    'ContentType': file.content_type,
                    'ServerSideEncryption': 'AES256'
                }
            )
            
            return s3_path
            
        except ClientError as e:
            print(f"Error uploading file to S3: {e}")
            raise

    def get_file_url(self, file_path):
        """
        Generate a temporary URL for file access
        """
        try:
            url = self.s3_client.generate_presigned_url(
                'get_object',
                Params={
                    'Bucket': S3_BUCKET_NAME,
                    'Key': file_path
                },
                ExpiresIn=URL_EXPIRATION
            )
            return url
        except ClientError as e:
            print(f"Error generating URL: {e}")
            raise

    def delete_file(self, file_path):
        """
        Delete a file from S3
        """
        try:
            self.s3_client.delete_object(
                Bucket=S3_BUCKET_NAME,
                Key=file_path
            )
        except ClientError as e:
            print(f"Error deleting file from S3: {e}")
            raise

    def validate_file(self, file):
        """
        Validate file size and type
        """
        # Check file size
        if file.content_length > MAX_FILE_SIZE:
            raise ValueError(f"File size exceeds {MAX_FILE_SIZE/1024/1024}MB limit")

        # Check file type
        file_ext = os.path.splitext(file.filename)[1].lower().lstrip('.')
        if file_ext not in ALLOWED_EXTENSIONS:
            raise ValueError(f"File type not allowed. Allowed types: {', '.join(ALLOWED_EXTENSIONS.keys())}")

        return True 