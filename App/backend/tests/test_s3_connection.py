import boto3
import os
from dotenv import load_dotenv
from botocore.config import Config

def test_s3_connection():
    try:
        # Load environment variables
        load_dotenv()
        
        # Print configuration (without secret key)
        print("Configuration:")
        print(f"Region: {os.getenv('AWS_REGION')}")
        print(f"Access Key ID: {os.getenv('AWS_ACCESS_KEY_ID')}")
        print(f"Bucket: {os.getenv('S3_BUCKET_NAME')}")
        
        # Create S3 client with specific config
        my_config = Config(
            region_name=os.getenv('AWS_REGION'),
            signature_version='s3v4'
        )
        
        s3_client = boto3.client(
            's3',
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
            config=my_config
        )
        
        # Try to list buckets
        print("\nTesting connection...")
        response = s3_client.list_buckets()
        
        # Print buckets
        print("S3 Connection Successful!")
        print("\nAvailable buckets:")
        for bucket in response['Buckets']:
            print(f"- {bucket['Name']}")
            
    except Exception as e:
        print(f"\nError connecting to S3: {str(e)}")
        if "SignatureDoesNotMatch" in str(e):
            print("\nPossible issues:")
            print("1. Check if there are any hidden characters in your .env file")
            print("2. Verify the AWS region matches your bucket's region")
            print("3. Make sure your system time is accurate")
            print("4. Try creating new access keys if the issue persists")

if __name__ == "__main__":
    test_s3_connection() 