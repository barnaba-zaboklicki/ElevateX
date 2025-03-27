import os
import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

load_dotenv()

def get_s3_client():
    """Create and return an S3 client."""
    return boto3.client(
        's3',
        region_name=os.getenv('AWS_REGION', 'eu-west-2')
    )

def upload_file_to_s3(file_obj, filename, content_type):
    """
    Upload a file to S3.
    
    Args:
        file_obj: File object to upload
        filename: Name to give the file in S3
        content_type: MIME type of the file
    
    Returns:
        dict: Dictionary containing the upload result
    """
    try:
        s3_client = get_s3_client()
        bucket_name = os.getenv('S3_BUCKET_NAME', 'elevatex-inventions')
        
        # Upload the file
        s3_client.upload_fileobj(
            file_obj,
            bucket_name,
            filename,
            ExtraArgs={
                'ContentType': content_type
            }
        )
        
        # Generate a presigned URL for the uploaded file
        url = generate_presigned_url(filename)
        
        return {
            'success': True,
            'message': 'File uploaded successfully',
            'filename': filename,
            'url': url
        }
    
    except ClientError as e:
        return {
            'success': False,
            'message': str(e),
            'error': e.response['Error']['Message']
        }
    except Exception as e:
        return {
            'success': False,
            'message': str(e)
        }

def generate_presigned_url(filename, expiration=3600):
    """
    Generate a presigned URL for accessing a file.
    
    Args:
        filename: Name of the file in S3
        expiration: URL expiration time in seconds (default 1 hour)
    
    Returns:
        str: Presigned URL for the file
    """
    try:
        s3_client = get_s3_client()
        bucket_name = os.getenv('S3_BUCKET_NAME', 'elevatex-inventions')
        
        url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': bucket_name,
                'Key': filename
            },
            ExpiresIn=expiration
        )
        
        return url
    except Exception as e:
        print(f"Error generating presigned URL: {str(e)}")
        return None

def delete_file_from_s3(filename):
    """
    Delete a file from S3.
    
    Args:
        filename: Name of the file to delete
    
    Returns:
        dict: Dictionary containing the deletion result
    """
    try:
        s3_client = get_s3_client()
        bucket_name = os.getenv('S3_BUCKET_NAME', 'elevatex-inventions')
        
        s3_client.delete_object(
            Bucket=bucket_name,
            Key=filename
        )
        
        return {
            'success': True,
            'message': 'File deleted successfully',
            'filename': filename
        }
    except Exception as e:
        return {
            'success': False,
            'message': str(e)
        } 