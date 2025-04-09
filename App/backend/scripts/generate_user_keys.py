import os
import sys
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import b64encode, b64decode
import hashlib

def generate_key_pair():
    """Generate RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key

def encrypt_private_key(private_key, password_hash):
    """Encrypt private key with password hash"""
    # Use the bcrypt hash as the key directly
    # We'll hash it with SHA-256 to get a 32-byte key
    key = hashlib.sha256(password_hash.encode()).digest()
    
    # Generate a random IV
    iv = os.urandom(16)
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv)
    )
    
    # Serialize private key
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Pad the data
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(private_key_bytes) + padder.finalize()
    
    # Encrypt
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Combine IV and encrypted data
    return b64encode(iv + encrypted_data).decode('utf-8')

def get_public_key(private_key):
    """Get public key in PEM format"""
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

def main():
    if len(sys.argv) != 2:
        print("Usage: python generate_user_keys.py <bcrypt_password_hash>")
        sys.exit(1)
    
    password_hash = sys.argv[1]
    
    try:
        # Generate key pair
        private_key = generate_key_pair()
        
        # Get public key
        public_key_pem = get_public_key(private_key)
        
        # Encrypt private key
        encrypted_private_key = encrypt_private_key(private_key, password_hash)
        
        # Output in format ready for database insertion
        output = {
            "public_key": public_key_pem,
            "encrypted_private_key": encrypted_private_key
        }
        
        print(json.dumps(output, indent=2))
        
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main() 