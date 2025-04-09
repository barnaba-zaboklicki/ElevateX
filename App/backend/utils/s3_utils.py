import os
import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from config.s3_config import URL_EXPIRATION
import io
from datetime import datetime
import base64
import json

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
        print("\n=== S3 File Upload Debug Logs ===")
        s3_client = get_s3_client()
        bucket_name = os.getenv('S3_BUCKET_NAME', 'elevatex-inventions')
        
        # Validate file object
        if not file_obj:
            print("Error: No file object provided")
            return {
                'success': False,
                'message': 'No file object provided'
            }
            
        # Get file size before upload
        file_obj.seek(0, os.SEEK_END)
        file_size = file_obj.tell()
        file_obj.seek(0)
        
        if file_size == 0:
            print("Error: File is empty")
            return {
                'success': False,
                'message': 'File is empty'
            }
            
        print(f"Uploading file: {filename}")
        print(f"File size: {file_size} bytes")
        print(f"Content type: {content_type}")
        
        # Upload the file
        s3_client.upload_fileobj(
            file_obj,
            bucket_name,
            filename,
            ExtraArgs={
                'ContentType': content_type
            }
        )
        
        # Verify the upload by checking the object
        try:
            response = s3_client.head_object(Bucket=bucket_name, Key=filename)
            print(f"Upload verified. Object size: {response['ContentLength']} bytes")
        except ClientError as e:
            print(f"Warning: Could not verify upload: {str(e)}")
        
        # Generate a presigned URL for the uploaded file
        url = generate_presigned_url(filename)
        
        # Create the full S3 key with s3:// prefix
        full_s3_key = f"s3://{bucket_name}/{filename}"
        
        print("=== End S3 File Upload Debug Logs ===\n")
        return {
            'success': True,
            'message': 'File uploaded successfully',
            'filename': filename,
            'url': url,
            's3_key': full_s3_key
        }
    
    except ClientError as e:
        print(f"Error uploading to S3: {str(e)}")
        return {
            'success': False,
            'message': str(e),
            'error': e.response['Error']['Message']
        }
    except Exception as e:
        print(f"Unexpected error during upload: {str(e)}")
        return {
            'success': False,
            'message': str(e)
        }

def generate_presigned_url(filename, expiration=URL_EXPIRATION):
    """
    Generate a presigned URL for accessing a file.
    
    Args:
        filename: Name of the file in S3
        expiration: URL expiration time in seconds (default from config)
    
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
        
        print(f"Attempting to delete file from S3: {filename} in bucket: {bucket_name}")  # Debug log
        
        # Extract the key from the S3 URL
        if 'amazonaws.com' in filename:
            # If it's a full URL, extract the key after the bucket name
            key = filename.split(bucket_name + '/')[1]
        else:
            # If it's already a key, use it as is
            key = filename
        
        print(f"Extracted S3 key: {key}")  # Debug log
        
        # Check if file exists before attempting deletion
        try:
            s3_client.head_object(Bucket=bucket_name, Key=key)
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                print(f"File not found in S3: {key}")  # Debug log
                return {
                    'success': True,
                    'message': 'File not found in S3',
                    'filename': key
                }
            else:
                raise
        
        # Delete the file
        s3_client.delete_object(
            Bucket=bucket_name,
            Key=key
        )
        
        print(f"Successfully deleted file from S3: {key}")  # Debug log
        
        return {
            'success': True,
            'message': 'File deleted successfully',
            'filename': key
        }
    except Exception as e:
        print(f"Error deleting file from S3: {str(e)}")  # Debug log
        return {
            'success': False,
            'message': str(e)
        }

def get_file_from_s3(filename):
    """
    Get a file directly from S3.
    
    Args:
        filename: Name of the file in S3
    
    Returns:
        dict: Dictionary containing the file data and metadata
    """
    try:
        print("\n=== S3 File Retrieval Debug Logs ===")
        print(f"Creating S3 client for file: {filename}")
        s3_client = get_s3_client()
        bucket_name = os.getenv('S3_BUCKET_NAME', 'elevatex-inventions')
        print(f"Using bucket: {bucket_name}")
        
        # First, check if the object exists and get its metadata
        print(f"Checking if object exists in S3: {filename}")
        try:
            head_response = s3_client.head_object(Bucket=bucket_name, Key=filename)
            print(f"Object exists in S3. Size: {head_response['ContentLength']} bytes")
            print(f"Content type: {head_response['ContentType']}")
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                print("Object not found in S3")
                return None
            else:
                raise
        
        # Get the file from S3
        print(f"Attempting to get object from S3 with key: {filename}")
        response = s3_client.get_object(
            Bucket=bucket_name,
            Key=filename
        )
        print("Successfully retrieved object from S3")
        print(f"Content type: {response.get('ContentType')}")
        print(f"Content length: {response.get('ContentLength')}")
        
        # Validate the response
        if not response.get('Body'):
            print("Error: No body in response")
            return None
            
        content_length = response.get('ContentLength', 0)
        if content_length == 0:
            print("Error: Content length is 0")
            return None
            
        # Read the content to verify it's not empty
        content = response['Body'].read()
        if not content:
            print("Error: Content is empty")
            return None
            
        # Reset the body stream for later use
        response['Body'] = io.BytesIO(content)
        
        print("=== End S3 File Retrieval Debug Logs ===\n")
        return response
        
    except ClientError as e:
        print("\n=== S3 File Retrieval Error Logs ===")
        print(f"AWS ClientError getting file from S3: {str(e)}")
        print(f"Error code: {e.response['Error']['Code']}")
        print(f"Error message: {e.response['Error']['Message']}")
        print("=== End S3 File Retrieval Error Logs ===\n")
        return None
    except Exception as e:
        print("\n=== S3 File Retrieval Error Logs ===")
        print(f"Error getting file from S3: {str(e)}")
        print(f"Error type: {type(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        print("=== End S3 File Retrieval Error Logs ===\n")
        return None

def store_encrypted_message(chat_id, message_id, encrypted_content):
    """
    Store an encrypted message in AWS S3.
    
    Args:
        chat_id (int): The ID of the chat
        message_id (int): The ID of the message
        encrypted_content (str): The encrypted message content (either JSON string or base64)
        
    Returns:
        dict: A dictionary containing success status and S3 key or error message
    """
    try:
        # Initialize S3 client
        s3_client = boto3.client(
            's3',
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
            region_name=os.getenv('AWS_REGION')
        )
        
        # Get bucket name from environment
        bucket_name = os.getenv('S3_BUCKET_NAME', 'elevatex-inventions')
        if not bucket_name:
            raise ValueError("S3_BUCKET_NAME environment variable is not set")
            
        print(f"Storing message in S3 - Chat ID: {chat_id}, Message ID: {message_id}")
        print(f"Encrypted content type: {type(encrypted_content)}")
        print(f"Encrypted content length: {len(encrypted_content)}")
        
        # Generate a unique key for the message
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        s3_key = f"chats/messages/{chat_id}/{message_id}_{timestamp}.enc"
        print(f"Generated S3 key: {s3_key}")
        
        # Check if content is already JSON
        try:
            # Try to parse as JSON to validate structure
            json.loads(encrypted_content)
            # If it's valid JSON, store it directly
            content_to_store = encrypted_content.encode('utf-8')
        except json.JSONDecodeError:
            # If not JSON, assume it's base64 and decode it
            try:
                content_to_store = base64.b64decode(encrypted_content)
            except Exception as e:
                print(f"Error decoding base64 content: {str(e)}")
                raise ValueError(f"Invalid content format: {str(e)}")
        
        # Upload to S3
        print(f"Uploading to S3 bucket: {bucket_name}")
        s3_client.put_object(
            Bucket=bucket_name,
            Key=s3_key,
            Body=content_to_store,
            ContentType='application/json' if isinstance(content_to_store, bytes) and content_to_store.startswith(b'{') else 'application/octet-stream',
            ServerSideEncryption='AES256'
        )
        
        return {
            'success': True,
            's3_key': s3_key
        }
        
    except ClientError as e:
        print(f"AWS S3 error: {str(e)}")
        return {
            'success': False,
            'message': f"AWS S3 error: {str(e)}"
        }
    except Exception as e:
        print(f"Unexpected error storing message in S3: {str(e)}")
        return {
            'success': False,
            'message': str(e)
        }

def get_message_from_s3(s3_key):
    """
    Retrieve an encrypted message from AWS S3.
    
    Args:
        s3_key (str): The S3 key of the message
        
    Returns:
        dict: A dictionary containing success status and message content or error message
    """
    try:
        # Initialize S3 client
        s3_client = boto3.client(
            's3',
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
            region_name=os.getenv('AWS_REGION')
        )
        
        # Get bucket name from environment
        bucket_name = os.getenv('S3_BUCKET_NAME', 'elevatex-inventions')
        if not bucket_name:
            raise ValueError("S3_BUCKET_NAME environment variable is not set")
        
        # Get object from S3
        response = s3_client.get_object(
            Bucket=bucket_name,
            Key=s3_key
        )
        
        # Read content
        content = response['Body'].read()
        
        # Check if content is JSON
        try:
            # Try to decode as UTF-8 and parse as JSON
            content_str = content.decode('utf-8')
            json.loads(content_str)  # Validate JSON structure
            return {
                'success': True,
                'content': content_str
            }
        except (UnicodeDecodeError, json.JSONDecodeError):
            # If not JSON, encode as base64
            return {
                'success': True,
                'content': base64.b64encode(content).decode('utf-8')
            }
        
    except ClientError as e:
        print(f"AWS S3 error retrieving message: {str(e)}")
        return {
            'success': False,
            'error': f"AWS S3 error: {str(e)}"
        }
    except Exception as e:
        print(f"Unexpected error retrieving message from S3: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        } 