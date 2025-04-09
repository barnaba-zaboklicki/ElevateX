class CryptoUtils {
    static async generateRSAKeyPair() {
        return await window.crypto.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256'
            },
            true,
            ['encrypt', 'decrypt']
        );
    }

    static async exportKey(key, format) {
        const exported = await window.crypto.subtle.exportKey(format, key);
        return this.arrayBufferToBase64(exported);
    }

    static async importKey(keyData, format, type, usages) {
        const keyBuffer = this.base64ToArrayBuffer(keyData);
        return await window.crypto.subtle.importKey(
            format,
            keyBuffer,
            {
                name: 'RSA-OAEP',
                hash: 'SHA-256'
            },
            true,
            usages
        );
    }

    static async encryptMessage(content, publicKey) {
        try {
            console.log('ENCRYPTION PROCESS: Starting encryption with:', {
                contentLength: content.length,
                contentFirstChars: content.substring(0, 10) + '...',
                publicKeyType: publicKey.type,
                publicKeyAlgorithm: publicKey.algorithm.name,
                publicKeyExtractable: publicKey.extractable,
                publicKeyUsages: publicKey.usages
            });

            // Export the public key to verify what we're using
            try {
                const exportedKey = await window.crypto.subtle.exportKey('spki', publicKey);
                const keyHash = await window.crypto.subtle.digest('SHA-256', exportedKey);
                const hashArray = Array.from(new Uint8Array(keyHash));
                const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                
                console.log('Public key verification for encryption:', {
                    publicKeyFingerprint: hashHex.substring(0, 16) + '...',
                    isPublicKey: publicKey.type === 'public',
                    canEncrypt: publicKey.usages.includes('encrypt')
                });
            } catch (e) {
                console.error('Could not generate public key fingerprint:', e);
            }

            // Generate a random AES key
            const aesKey = await window.crypto.subtle.generateKey(
                {
                    name: 'AES-GCM',
                    length: 256
                },
                true,
                ['encrypt']
            );

            console.log('AES key generated successfully:', {
                type: aesKey.type,
                algorithm: aesKey.algorithm.name,
                extractable: aesKey.extractable,
                usages: aesKey.usages
            });

            // Export the AES key
            const exportedAesKey = await window.crypto.subtle.exportKey('raw', aesKey);
            console.log('AES key exported successfully, length:', exportedAesKey.byteLength);

            // Encrypt the AES key with RSA
            console.log('Attempting RSA encryption of AES key...');
            const encryptedKey = await window.crypto.subtle.encrypt(
                {
                    name: 'RSA-OAEP',
                    hash: 'SHA-256'
                },
                publicKey,
                exportedAesKey
            );

            console.log('AES key encrypted successfully, length:', encryptedKey.byteLength);

            // Generate a random IV
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            console.log('IV generated successfully:', {
                type: iv.constructor.name,
                length: iv.byteLength,
                firstBytes: Array.from(iv.slice(0, 4))
            });

            // Encrypt the content with AES
            console.log('Attempting AES encryption of content...');
            const encryptedContent = await window.crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                aesKey,
                new TextEncoder().encode(content)
            );

            console.log('Content encrypted successfully:', {
                originalLength: content.length,
                encryptedLength: encryptedContent.byteLength,
                encryptionRatio: (encryptedContent.byteLength / content.length).toFixed(2)
            });

            const result = {
                encrypted_key: this.arrayBufferToBase64(encryptedKey),
                encrypted_content: this.arrayBufferToBase64(encryptedContent),
                iv: this.arrayBufferToBase64(iv)
            };

            console.log('Final encrypted data structure:', {
                encrypted_key_length: result.encrypted_key.length,
                encrypted_content_length: result.encrypted_content.length,
                iv_length: result.iv.length,
                total_size: result.encrypted_key.length + result.encrypted_content.length + result.iv.length
            });

            return result;
        } catch (error) {
            console.error('Error in encryptMessage:', error);
            console.error('Error details:', {
                name: error.name,
                message: error.message,
                stack: error.stack
            });
            throw error;
        }
    }

    static async decryptMessage(encryptedData, privateKey) {
        try {
            console.log('DECRYPTION PROCESS: Starting decryption with:', {
                keyLength: encryptedData.encrypted_key.length,
                contentLength: encryptedData.encrypted_content.length,
                ivLength: encryptedData.iv ? (typeof encryptedData.iv === 'string' ? encryptedData.iv.length : encryptedData.iv.byteLength) : 0,
                privateKeyType: privateKey.type,
                privateKeyAlgorithm: privateKey.algorithm.name,
                privateKeyExtractable: privateKey.extractable,
                privateKeyUsages: privateKey.usages
            });

            // Verify the private key we're using for decryption
            try {
                // We can't export the private key directly, but we can check its properties via JWK
                const jwk = await window.crypto.subtle.exportKey('jwk', privateKey);
                console.log('Private key verification for decryption:', {
                    alg: jwk.alg,
                    key_ops: jwk.key_ops,
                    ext: jwk.ext,
                    isPrivateKey: privateKey.type === 'private',
                    canDecrypt: privateKey.usages.includes('decrypt'),
                    modulusFirstChars: jwk.n ? jwk.n.substring(0, 8) + '...' : 'N/A'
                });
            } catch (e) {
                console.error('Could not verify private key:', e);
            }

            // Convert base64 strings to ArrayBuffer
            const encryptedKeyBuffer = this.base64ToArrayBuffer(encryptedData.encrypted_key);
            const encryptedContentBuffer = this.base64ToArrayBuffer(encryptedData.encrypted_content);

            console.log('Converted to ArrayBuffer:', {
                keyBufferLength: encryptedKeyBuffer.byteLength,
                contentBufferLength: encryptedContentBuffer.byteLength,
                keyBufferFirstBytes: Array.from(new Uint8Array(encryptedKeyBuffer.slice(0, 4))),
                contentBufferFirstBytes: Array.from(new Uint8Array(encryptedContentBuffer.slice(0, 4)))
            });

            // Validate private key
            if (!privateKey || privateKey.type !== 'private' || privateKey.algorithm.name !== 'RSA-OAEP') {
                throw new Error('Invalid private key format');
            }

            // Decrypt the AES key with RSA
            console.log('Attempting RSA decryption of AES key...');
            let decryptedKey;
            try {
                decryptedKey = await window.crypto.subtle.decrypt(
                    {
                        name: 'RSA-OAEP',
                        hash: 'SHA-256'
                    },
                    privateKey,
                    encryptedKeyBuffer
                );
                console.log('AES key decrypted successfully, length:', decryptedKey.byteLength);
            } catch (error) {
                console.error('RSA decryption failed:', {
                    error: error.message,
                    name: error.name,
                    stack: error.stack,
                    encryptedKeyLength: encryptedKeyBuffer.byteLength,
                    privateKeyType: privateKey.type,
                    privateKeyUsages: privateKey.usages
                });
                throw error;
            }

            // Import the decrypted AES key
            console.log('Importing decrypted AES key...');
            let aesKey;
            try {
                aesKey = await window.crypto.subtle.importKey(
                    'raw',
                    decryptedKey,
                    {
                        name: 'AES-GCM',
                        length: 256
                    },
                    false,
                    ['decrypt']
                );

                console.log('AES key imported successfully:', {
                    type: aesKey.type,
                    algorithm: aesKey.algorithm.name,
                    extractable: aesKey.extractable,
                    usages: aesKey.usages
                });
            } catch (error) {
                console.error('AES key import failed:', error);
                throw new Error('Failed to import AES key: ' + error.message);
            }

            // Ensure IV is a Uint8Array
            let iv;
            try {
                // Check if iv is already an ArrayBuffer or Uint8Array
                if (encryptedData.iv instanceof ArrayBuffer || encryptedData.iv instanceof Uint8Array) {
                    iv = encryptedData.iv;
                    console.log('Using provided ArrayBuffer IV');
                } else if (typeof encryptedData.iv === 'string') {
                    // Convert from base64 string
                    iv = this.base64ToArrayBuffer(encryptedData.iv);
                    console.log('Converted IV from base64 string to ArrayBuffer');
                } else {
                    console.error('Invalid IV format:', typeof encryptedData.iv);
                    // Fallback to a fixed IV (not secure but allows decryption to attempt to proceed)
                    iv = new Uint8Array(12);
                    console.warn('Using fallback fixed IV');
                }

                console.log('Using IV:', {
                    type: iv.constructor.name,
                    length: iv.byteLength,
                    firstBytes: Array.from(new Uint8Array(iv instanceof ArrayBuffer ? iv : iv.buffer).slice(0, 4))
                });
            } catch (error) {
                console.error('IV processing failed:', error);
                throw new Error('Failed to process IV: ' + error.message);
            }

            // Decrypt the content with AES
            console.log('Attempting AES decryption of content...');
            let decryptedContent;
            try {
                decryptedContent = await window.crypto.subtle.decrypt(
                    {
                        name: 'AES-GCM',
                        iv: iv
                    },
                    aesKey,
                    encryptedContentBuffer
                );

                console.log('Content decrypted successfully:', {
                    encryptedLength: encryptedContentBuffer.byteLength,
                    decryptedLength: decryptedContent.byteLength,
                    ratio: (decryptedContent.byteLength / encryptedContentBuffer.byteLength).toFixed(2)
                });
            } catch (error) {
                console.error('AES decryption failed:', {
                    error: error.message,
                    name: error.name,
                    ivLength: iv.byteLength,
                    contentLength: encryptedContentBuffer.byteLength
                });
                throw new Error('Failed to decrypt content: ' + error.message);
            }

            // Convert decrypted content to string
            const result = new TextDecoder().decode(decryptedContent);
            console.log('Decrypted message:', {
                length: result.length,
                preview: result.substring(0, 20) + (result.length > 20 ? '...' : '')
            });
            
            return result;
        } catch (error) {
            console.error('Error in decryptMessage:', error);
            console.error('Error details:', {
                name: error.name,
                message: error.message,
                stack: error.stack
            });
            throw error;
        }
    }

    static async encryptPrivateKey(privateKey) {
        // Generate a random AES key for encrypting the private key
        const aesKey = await window.crypto.subtle.generateKey(
            {
                name: 'AES-GCM',
                length: 256
            },
            true,
            ['encrypt']
        );

        // Export the private key
        const exportedPrivateKey = await this.exportKey(privateKey, 'pkcs8');

        // Encrypt the private key with AES
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encryptedPrivateKey = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            aesKey,
            new TextEncoder().encode(exportedPrivateKey)
        );

        // Export the AES key
        const exportedAesKey = await this.exportKey(aesKey, 'raw');

        return {
            encrypted_key: exportedAesKey,
            encrypted_content: this.arrayBufferToBase64(encryptedPrivateKey),
            iv: this.arrayBufferToBase64(iv)
        };
    }

    static async decryptPrivateKey(encrypted_data, password_hash) {
        try {
            console.log('Starting private key decryption with:', {
                encrypted_data_length: encrypted_data.length,
                password_hash_length: password_hash.length
            });

            // The password_hash is already a bcrypt hash, we need to hash it with SHA-256
            const keyBuffer = await window.crypto.subtle.digest(
                'SHA-256',
                new TextEncoder().encode(password_hash)
            );
            console.log('Generated key buffer length:', keyBuffer.byteLength);
            
            // Import the key for AES-CBC
            const key = await window.crypto.subtle.importKey(
                'raw',
                keyBuffer,
                { name: 'AES-CBC', length: 256 },
                false,
                ['decrypt']
            );
            console.log('Key imported successfully');

            // Convert the encrypted data to ArrayBuffer
            const encryptedBuffer = this.base64ToArrayBuffer(encrypted_data);
            console.log('Encrypted buffer length:', encryptedBuffer.byteLength);
            
            // Extract IV (first 16 bytes) and encrypted content (remaining bytes)
            const iv = encryptedBuffer.slice(0, 16);
            const encryptedContent = encryptedBuffer.slice(16);
            console.log('IV length:', iv.byteLength, 'Content length:', encryptedContent.byteLength);

            // Decrypt the private key
            const decrypted = await window.crypto.subtle.decrypt(
                {
                    name: 'AES-CBC',
                    iv: iv
                },
                key,
                encryptedContent
            );
            console.log('Decrypted data length:', decrypted.byteLength);

            // Remove PKCS7 padding
            const paddingLength = new Uint8Array(decrypted)[decrypted.byteLength - 1];
            console.log('Padding length:', paddingLength);
            
            if (paddingLength > 16 || paddingLength === 0) {
                throw new Error(`Invalid padding length: ${paddingLength}`);
            }

            const unpaddedData = decrypted.slice(0, decrypted.byteLength - paddingLength);
            console.log('Unpadded data length:', unpaddedData.byteLength);

            // Convert the decrypted data to a string to handle PEM format
            const pemString = new TextDecoder().decode(unpaddedData);
            console.log('PEM string:', pemString.substring(0, 50) + '...');

            // Extract and log the modulus to verify key correctness
            try {
                // Extract the modulus from the PEM
                const base64Data = pemString.split('-----')[2].trim();
                const asn1Data = this.base64ToArrayBuffer(base64Data);
                console.log('ASN.1 data length:', asn1Data.byteLength);
                // Log a checksum of the key data for comparison
                const keyChecksum = await window.crypto.subtle.digest('SHA-256', asn1Data);
                const checksumArray = Array.from(new Uint8Array(keyChecksum));
                const checksumHex = checksumArray.map(b => b.toString(16).padStart(2, '0')).join('');
                console.log('Private key checksum (first 16 chars):', checksumHex.substring(0, 16));
            } catch (e) {
                console.error('Error extracting key details:', e);
            }

            // Import the decrypted private key as PEM
            const privateKey = await window.crypto.subtle.importKey(
                'pkcs8',
                this.base64ToArrayBuffer(pemString.split('-----')[2].trim()),
                {
                    name: 'RSA-OAEP',
                    hash: 'SHA-256'
                },
                true, // Make extractable for debugging
                ['decrypt']
            );
            console.log('Private key imported successfully:', {
                type: privateKey.type,
                algorithm: privateKey.algorithm.name,
                extractable: privateKey.extractable,
                usages: privateKey.usages
            });

            return privateKey;
        } catch (error) {
            console.error('Error in decryptPrivateKey:', error);
            console.error('Error details:', {
                name: error.name,
                message: error.message,
                stack: error.stack
            });
            throw error;
        }
    }

    static arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    static base64ToArrayBuffer(base64) {
        try {
            // Validate base64 string
            if (!base64 || typeof base64 !== 'string') {
                throw new Error('Invalid base64 input: must be a non-empty string');
            }

            // Remove any whitespace, newlines, and escaped newlines
            base64 = base64.replace(/\\n/g, '').replace(/\s+/g, '').trim();
            
            // Check if the string is valid base64
            if (!/^[A-Za-z0-9+/]*={0,2}$/.test(base64)) {
                console.error('Invalid base64 string:', base64);
                throw new Error('Invalid base64 string: contains invalid characters');
            }

            // Ensure the string length is a multiple of 4
            const padding = base64.length % 4;
            if (padding) {
                base64 += '='.repeat(4 - padding);
            }

            const binary = atob(base64);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes.buffer;
        } catch (error) {
            console.error('Error in base64ToArrayBuffer:', error);
            console.error('Input base64 string:', base64);
            throw error;
        }
    }
}

class Chat {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.messages = [];
        this.polling = false;
        this.initialized = false;
        this.accessToken = localStorage.getItem('token');
        
        if (!this.container) {
            throw new Error(`Container with id ${containerId} not found`);
        }

        this.inventorName = '';
        this.inventionTitle = '';
        this.chatId = '';
        this.otherUserId = '';
        this.pollingInterval = null;
        this.privateKey = null;
        this.otherUserPublicKey = null;
    }

    async initialize(chatId, otherUserId) {
        try {
            this.chatId = chatId;
            this.otherUserId = otherUserId;
            
            // First, render the chat UI so container elements exist
            this.render();
            
            // Fetch and decrypt the private key
            await this.fetchAndDecryptPrivateKey();
            
            // Fetch the other user's public key
            await this.fetchOtherUserPublicKey();
            
            // Test if the keys are working properly with a simple test
            if (!await this.testEncryptionKeys()) {
                console.warn('Encryption keys failed test. Regenerating keys...');
                await this.regenerateAndUploadKeys();
                // Fetch the new keys
                await this.fetchAndDecryptPrivateKey();
                await this.fetchOtherUserPublicKey();
                // Test again
                if (!await this.testEncryptionKeys()) {
                    console.error('Keys still failing after regeneration. User may need to logout and login again.');
                }
            }
            
            // Load messages
            await this.loadMessages();
            
            // Start polling for new messages
            this.startPolling();
            
            this.initialized = true;
            console.log('Chat initialized successfully');
        } catch (error) {
            console.error('Error initializing chat:', error);
            throw error;
        }
    }

    async checkUserKeys() {
        try {
            const response = await fetch('https://127.0.0.1:5000/api/keys/user/me', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${this.accessToken}`,
                    'Content-Type': 'application/json'
                }
            });

            console.log('Key check response status:', response.status);
            console.log('Key check response headers:', Object.fromEntries(response.headers.entries()));

            if (response.status === 404) {
                console.log('No keys found for user');
                return false;
            }

            if (response.status === 422) {
                console.log('Keys exist but are invalid');
                return false;
            }

            if (!response.ok) {
                throw new Error(`Failed to check user keys: ${response.statusText}`);
            }

            const data = await response.json();
            console.log('Key check response data:', {
                public_key: data.public_key ? 'Present' : 'Missing',
                encrypted_private_key: data.encrypted_private_key ? 'Present' : 'Missing'
            });

            // Check if we have both required keys
            if (!data.public_key || !data.encrypted_private_key) {
                console.log('Missing required keys');
                return false;
            }

            return true;
        } catch (error) {
            console.error('Error checking user keys:', error);
            return false;
        }
    }

    async generateAndUploadKeys() {
        try {
            const token = localStorage.getItem('token');
            if (!token) {
                throw new Error('No access token found');
            }

            // Generate RSA key pair
            const { publicKey, privateKey } = await CryptoUtils.generateRSAKeyPair();
            
            // Export public key in SPKI format
            const publicKeyData = await window.crypto.subtle.exportKey('spki', publicKey);
            const publicKeyBase64 = CryptoUtils.arrayBufferToBase64(publicKeyData);
            
            // Export private key in PKCS8 format
            const privateKeyData = await window.crypto.subtle.exportKey('pkcs8', privateKey);
            const privateKeyBase64 = CryptoUtils.arrayBufferToBase64(privateKeyData);
            
            // Get password hash from localStorage
            const passwordHash = localStorage.getItem('password_hash');
            if (!passwordHash) {
                throw new Error('Password hash not found in localStorage');
            }

            // Import password hash as key
            const passwordKey = await window.crypto.subtle.importKey(
                'raw',
                CryptoUtils.base64ToArrayBuffer(passwordHash),
                {
                    name: 'PBKDF2'
                },
                false,
                ['deriveBits', 'deriveKey']
            );

            // Derive AES key from password
            const aesKey = await window.crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: new TextEncoder().encode('salt'),
                    iterations: 100000,
                    hash: 'SHA-256'
                },
                passwordKey,
                {
                    name: 'AES-GCM',
                    length: 256
                },
                false,
                ['encrypt']
            );

            // Generate IV
            const iv = window.crypto.getRandomValues(new Uint8Array(12));

            // Encrypt private key
            const encryptedPrivateKey = await window.crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                aesKey,
                new TextEncoder().encode(privateKeyBase64)
            );

            // Combine IV and encrypted data into a single string
            const combinedData = new Uint8Array(iv.length + encryptedPrivateKey.byteLength);
            combinedData.set(iv);
            combinedData.set(new Uint8Array(encryptedPrivateKey), iv.length);
            const encryptedPrivateKeyBase64 = CryptoUtils.arrayBufferToBase64(combinedData);
            
            // Upload keys to server
            const response = await fetch('https://127.0.0.1:5000/api/keys/user/upload', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    public_key: publicKeyBase64,
                    encrypted_private_key: encryptedPrivateKeyBase64
                })
            });

            if (!response.ok) {
                const errorText = await response.text();
                console.error('Upload response:', errorText);
                throw new Error('Failed to upload keys');
            }

            console.log('Keys uploaded successfully');
        } catch (error) {
            console.error('Error generating and uploading keys:', error);
            throw error;
        }
    }

    async renderMessages() {
        const messagesContainer = this.container.querySelector('.chat-messages');
        if (!messagesContainer) return;

        // Clear existing messages
        messagesContainer.innerHTML = '';

        // Get current user ID from token for verification
        let currentUserId = null;
        try {
            const tokenParts = this.accessToken.split('.');
            if (tokenParts.length === 3) {
                const payload = JSON.parse(atob(tokenParts[1]));
                currentUserId = payload.sub || payload.user_id;
            }
        } catch (err) {
            console.error('Error parsing token:', err);
        }

        console.log('DECRYPTION KEY CHECK: Rendering messages with keys:', {
            currentUserId: currentUserId,
            otherUserId: this.otherUserId,
            usingPrivateKey: {
                type: this.privateKey.type,
                algorithm: this.privateKey.algorithm.name,
                extractable: this.privateKey.extractable,
                usages: this.privateKey.usages
            }
        });

        // Show loading spinner if no messages are being loaded yet
        if (this.messages.length === 0) {
            messagesContainer.innerHTML = `
                <div class="loading-messages">
                    <div class="loading-spinner" style="border: 4px solid #dddddd; border-top: 4px solid #ff0000; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin-bottom: 15px;"></div>
                    <p>Loading messages...</p>
                </div>
            `;
            return;
        }

        // Create a fingerprint for the private key for verification
        try {
            // We can't export the private key itself, but we can export its public counterpart
            // This creates a unique identifier without exposing sensitive data
            const jwk = await window.crypto.subtle.exportKey('jwk', this.privateKey);
            console.log('Private key JWK properties for verification:', {
                forUserId: currentUserId,
                kid: jwk.kid || 'not set',
                alg: jwk.alg,
                keyOps: jwk.key_ops.join(','),
                isPrivateKey: this.privateKey.type === 'private',
                keyUsage: this.privateKey.usages.includes('decrypt') ? 'Can decrypt' : 'Cannot decrypt'
            });
        } catch (e) {
            console.error('Failed to export private key properties:', e);
        }

        // For each message, create a placeholder first
        for (const message of this.messages) {
            const messageElement = document.createElement('div');
            messageElement.className = `message ${message.is_sender ? 'sent' : 'received'}`;
            messageElement.setAttribute('data-message-id', message.id || '');
            
            // Start with a loading placeholder
            messageElement.innerHTML = `
                <div class="message-content loading">
                    <div class="loading-spinner" style="border: 3px solid #dddddd; border-top: 3px solid #ff0000; border-radius: 50%; width: 15px; height: 15px; display: inline-block; animation: spin 1s linear infinite;"></div>
                    <p>${message.is_sender ? 'Processing your message...' : 'Decrypting message...'}</p>
                </div>
            `;
            
            messagesContainer.appendChild(messageElement);
        }

        // Scroll to bottom to show loading messages
        messagesContainer.scrollTop = messagesContainer.scrollHeight;

        // Process each message
        for (let i = 0; i < this.messages.length; i++) {
            try {
                const message = this.messages[i];
                const messageEl = messagesContainer.querySelector(`[data-message-id="${message.id || ''}"]`);
                if (!messageEl) continue;
                
                console.log('Processing message:', {
                    messageId: message.id,
                    senderId: message.sender_id,
                    isSender: message.is_sender,
                    currentUserId: currentUserId,
                    hasContent: !!message.content,
                    hasSelfEncrypted: !!message.self_encrypted_content,
                    contentLength: message.content ? message.content.length : 0,
                    shouldDecrypt: true
                });

                let messageContent;
                
                // For messages sent by the current user
                if (message.is_sender) {
                    // First try to use the original content if available in memory
                    if (message.content) {
                        messageContent = message.content;
                        console.log('Using stored original content for sent message');
                    } 
                    // Next try to decrypt using self-encrypted version
                    else if (message.self_encrypted_content) {
                        console.log('Attempting to decrypt self-encrypted message');
                        try {
                            let encryptedData;
                            
                            // Parse the self-encrypted content
                            try {
                                encryptedData = JSON.parse(message.self_encrypted_content);
                                console.log('Parsed self-encrypted data:', {
                                    keyLength: encryptedData.encrypted_key.length,
                                    contentLength: encryptedData.encrypted_content.length,
                                    hasIv: !!encryptedData.iv
                                });
                            } catch (parseError) {
                                console.error('Error parsing self-encrypted content:', parseError);
                                throw new Error('Invalid message format');
                            }
                            
                            // Ensure we have all required fields
                            if (!encryptedData.encrypted_key || !encryptedData.encrypted_content) {
                                console.error('Missing required fields in self-encrypted data');
                                throw new Error('Missing required fields in encrypted data');
                            }
                            
                            // Convert IV from base64 to Uint8Array if needed
                            if (encryptedData.iv && typeof encryptedData.iv === 'string') {
                                try {
                                    encryptedData.iv = CryptoUtils.base64ToArrayBuffer(encryptedData.iv);
                                } catch (ivError) {
                                    console.error('Error converting IV from base64:', ivError);
                                    encryptedData.iv = new Uint8Array(12);
                                }
                            }
                            
                            // Decrypt using your private key
                            messageContent = await CryptoUtils.decryptMessage(
                                encryptedData,
                                this.privateKey
                            );
                            
                            console.log('Successfully decrypted self-encrypted message');
                        } catch (decryptError) {
                            console.error('Failed to decrypt self-encrypted message:', decryptError);
                            messageContent = "[Your encrypted message]";
                        }
                    }
                    // Fall back to placeholder message
                    else {
                        messageContent = "[Your encrypted message]";
                        console.log('No decryptable content available for sent message');
                    }
                    
                    // Update the message element
                    if (messageEl) {
                        const isDecrypted = message.content || (message.self_encrypted_content && messageContent !== "[Your encrypted message]");
                        messageEl.innerHTML = `
                            <div class="message-content sent-message">
                                <p>${this.escapeHtml(messageContent)}</p>
                                <small>${new Date(message.created_at).toLocaleString()}</small>
                                ${isDecrypted ? '' : '<span class="encryption-note">⚠️ Original content not available</span>'}
                            </div>
                        `;
                    }
                    
                    console.log('Message was sent by current user, displaying appropriate content');
                } else {
                    // Only decrypt messages received from others
                    let encryptedData;
                    try {
                        // Try to parse as JSON first (new format)
                        if (typeof message.encrypted_content === 'string' && 
                            message.encrypted_content.startsWith('encryptedkey')) {
                            // Handle old format
                            const base64Data = message.encrypted_content.substring('encryptedkey'.length);
                            console.log('Processing old format message, base64 length:', base64Data.length);
                            
                            // The key is always 344 characters in base64
                            const keyLength = 344;
                            if (base64Data.length <= keyLength) {
                                console.error('Invalid old format message: content too short');
                                throw new Error('Invalid message format: content too short');
                            }
                            
                            const key = base64Data.substring(0, keyLength);
                            const content = base64Data.substring(keyLength);
                            
                            console.log('Split old format data:', {
                                keyLength: key.length,
                                contentLength: content.length,
                                key: key.substring(0, 20) + '...',
                                content: content.substring(0, 20) + '...'
                            });
                            
                            // For old format, we don't have IV stored, so we use a static one
                            // This is not secure but should work for old messages
                            // Use a fixed IV of 12 zeros for old messages
                            const fixedIv = new Uint8Array(12);
                            
                            encryptedData = {
                                encrypted_key: key,
                                encrypted_content: content,
                                iv: fixedIv
                            };
                            
                            console.log('Created encryptedData for old format with fixed IV');
                        } else {
                            // Handle new format
                            try {
                                encryptedData = JSON.parse(message.encrypted_content);
                                console.log('Parsed new format message:', {
                                    keyLength: encryptedData.encrypted_key.length,
                                    contentLength: encryptedData.encrypted_content.length,
                                    hasIv: !!encryptedData.iv
                                });
                            } catch (parseError) {
                                console.error('Error parsing JSON message:', parseError);
                                console.log('Trying to parse as legacy format without encryptedkey prefix');
                                
                                // Try to parse as raw base64 without prefix
                                const rawContent = message.encrypted_content;
                                // Assume the first 344 characters are the key
                                const key = rawContent.substring(0, 344);
                                const content = rawContent.substring(344);
                                
                                console.log('Attempting to parse as raw base64:', {
                                    rawContentLength: rawContent.length,
                                    keyLength: key.length,
                                    contentLength: content.length
                                });
                                
                                // Use fixed IV for this format too
                                const fixedIv = new Uint8Array(12);
                                
                                encryptedData = {
                                    encrypted_key: key,
                                    encrypted_content: content,
                                    iv: fixedIv
                                };
                            }
                        }
                    } catch (e) {
                        console.error('Error parsing message format:', e);
                        throw new Error('Invalid message format');
                    }

                    // Ensure we have all required fields
                    if (!encryptedData.encrypted_key || !encryptedData.encrypted_content) {
                        console.error('Missing required fields in encrypted data:', encryptedData);
                        throw new Error('Missing required fields in encrypted data');
                    }

                    // Convert IV from base64 to Uint8Array if present
                    if (encryptedData.iv && typeof encryptedData.iv === 'string') {
                        try {
                            encryptedData.iv = CryptoUtils.base64ToArrayBuffer(encryptedData.iv);
                            console.log('Converted IV from base64 to ArrayBuffer, length:', encryptedData.iv.byteLength);
                        } catch (ivError) {
                            console.error('Error converting IV from base64:', ivError);
                            // Fall back to fixed IV
                            encryptedData.iv = new Uint8Array(12);
                        }
                    }

                    // Log the data before decryption
                    console.log('Attempting decryption with:', {
                        keyLength: encryptedData.encrypted_key.length,
                        contentLength: encryptedData.encrypted_content.length,
                        ivLength: encryptedData.iv ? encryptedData.iv.byteLength : 0,
                        ivFirstBytes: encryptedData.iv ? Array.from(new Uint8Array(encryptedData.iv).slice(0, 4)) : [],
                        senderId: message.sender_id,
                        isSender: message.is_sender,
                        usingPrivateKeyType: this.privateKey.type,
                        usingPrivateKeyUsages: this.privateKey.usages
                    });

                    messageContent = await CryptoUtils.decryptMessage(
                        encryptedData,
                        this.privateKey
                    );
                    
                    // Update the message element with the decrypted content
                    if (messageEl) {
                        messageEl.innerHTML = `
                            <div class="message-content received-message">
                                <p>${this.escapeHtml(messageContent)}</p>
                                <small>${new Date(message.created_at).toLocaleString()}</small>
                            </div>
                        `;
                    }
                }
            } catch (error) {
                console.error('Error processing message:', error);
                const messageEl = messagesContainer.querySelector(`[data-message-id="${this.messages[i].id || ''}"]`);
                if (messageEl) {
                    const message = this.messages[i];
                    const errorMessage = message.is_sender 
                        ? 'This message was encrypted for the recipient and cannot be viewed'
                        : `Failed to decrypt message: ${error.message}`;
                    
                    messageEl.innerHTML = `
                        <div class="message-content ${message.is_sender ? 'encrypted-sender' : 'error'}">
                            <p>${errorMessage}</p>
                            <small>${new Date(message.created_at).toLocaleString()}</small>
                        </div>
                    `;
                }
            }
        }

        // Scroll to bottom after all messages are processed
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
        
        // Add CSS for the encryption note
        if (!document.getElementById('chat-encryption-styles')) {
            const style = document.createElement('style');
            style.id = 'chat-encryption-styles';
            style.textContent = `
                .encryption-note {
                    display: block;
                    font-size: 0.8em;
                    color: #888;
                    margin-top: 5px;
                    font-style: italic;
                }
                
                .message-content.encrypted-sender {
                    background-color: #ffefef;
                    border-left: 3px solid #ffaaaa;
                }
                
                .message-content.encrypted-sender p {
                    color: #666;
                    font-style: italic;
                }
            `;
            document.head.appendChild(style);
        }
    }

    escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    async sendMessage() {
        try {
            const textarea = this.container.querySelector('.chat-input textarea');
            const content = textarea.value.trim();
            if (!content) return;

            // Ensure chat is properly initialized
            if (!this.chatId || !this.otherUserPublicKey) {
                console.error('Chat not properly initialized:', {
                    chatId: this.chatId,
                    hasOtherUserPublicKey: !!this.otherUserPublicKey
                });
                throw new Error('Chat not properly initialized');
            }

            // Get current user ID from token
            let currentUserId = null;
            try {
                const tokenParts = this.accessToken.split('.');
                if (tokenParts.length === 3) {
                    const payload = JSON.parse(atob(tokenParts[1]));
                    currentUserId = payload.sub || payload.user_id;
                    console.log('Current user ID from token (sender):', currentUserId);
                }
            } catch (err) {
                console.error('Error parsing token:', err);
            }

            console.log('ENCRYPTION KEY CHECK: Sending message with keys:', {
                currentUserId: currentUserId,
                otherUserId: this.otherUserId,
                usingPublicKey: {
                    type: this.otherUserPublicKey.type,
                    algorithm: this.otherUserPublicKey.algorithm.name,
                    extractable: this.otherUserPublicKey.extractable,
                    usages: this.otherUserPublicKey.usages
                }
            });

            // Export public key to create a fingerprint for verification
            try {
                const exportedKey = await window.crypto.subtle.exportKey('spki', this.otherUserPublicKey);
                const keyFingerprint = await window.crypto.subtle.digest('SHA-256', exportedKey);
                const fingerprintArray = Array.from(new Uint8Array(keyFingerprint));
                const fingerprintHex = fingerprintArray.map(b => b.toString(16).padStart(2, '0')).join('');
                
                console.log('Public key fingerprint for encryption:', {
                    forUserId: this.otherUserId,
                    fingerprint: fingerprintHex.substring(0, 16) + '...',
                    isPublicKey: this.otherUserPublicKey.type === 'public',
                    keyUsage: this.otherUserPublicKey.usages.includes('encrypt') ? 'Can encrypt' : 'Cannot encrypt'
                });
            } catch (e) {
                console.error('Failed to generate key fingerprint:', e);
            }

            // STEP 1: Encrypt the message for the recipient using their public key
            const encryptedForRecipient = await CryptoUtils.encryptMessage(content, this.otherUserPublicKey);
            console.log('Message encrypted successfully for recipient:', {
                encryptedKeyLength: encryptedForRecipient.encrypted_key.length,
                encryptedContentLength: encryptedForRecipient.encrypted_content.length,
                ivLength: encryptedForRecipient.iv.length
            });

            // STEP 2: Fetch your own public key to encrypt a version for yourself
            console.log('Fetching own public key to encrypt message for self...');
            let encryptedForSelf = null;
            let myPublicKey = null;
            
            try {
                const token = localStorage.getItem('token');
                if (!token) {
                    throw new Error('No access token found');
                }
                
                const response = await fetch('https://127.0.0.1:5000/api/keys/user/me', {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                });
                
                if (!response.ok) {
                    throw new Error(`Failed to fetch own public key: ${response.statusText}`);
                }
                
                const data = await response.json();
                if (!data.public_key) {
                    throw new Error('No public key found in response');
                }
                
                // Import your own public key
                myPublicKey = await this.importPublicKey(data.public_key);
                console.log('Successfully imported own public key for self-encryption');
                
                // Encrypt the message for yourself using your public key
                encryptedForSelf = await CryptoUtils.encryptMessage(content, myPublicKey);
                console.log('Message encrypted successfully for self:', {
                    encryptedKeyLength: encryptedForSelf.encrypted_key.length,
                    encryptedContentLength: encryptedForSelf.encrypted_content.length,
                    ivLength: encryptedForSelf.iv.length
                });
            } catch (e) {
                console.error('Failed to encrypt message for self:', e);
                // Continue even if self-encryption fails - not critical
            }

            // Get access token
            const token = localStorage.getItem('token');
            if (!token) {
                throw new Error('No access token found');
            }

            // STEP 3: Create the final message structure with both encrypted versions
            // For the backend S3 storage, we need to structure the message differently
            // Since the backend expects a single encrypted_content string
            
            // Create a combined payload that includes both encrypted versions
            const combinedPayload = {
                recipient_encrypted: encryptedForRecipient,
                self_encrypted: encryptedForSelf
            };
            
            // Convert to string for the API
            const combinedPayloadString = JSON.stringify(combinedPayload);
            
            // Send the encrypted message with combined payload
            const response = await fetch(`https://127.0.0.1:5000/api/messages/${this.chatId}/send`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    encrypted_content: combinedPayloadString
                })
            });

            if (!response.ok) {
                throw new Error(`Failed to send message: ${response.statusText}`);
            }

            const data = await response.json();
            console.log('Message sent successfully:', {
                messageId: data.message.id,
                s3Key: data.message.s3_key,
                hasSelfEncryptedVersion: !!encryptedForSelf
            });

            // Add the sent message to the local messages array with the original content
            // This will only be available in the current session
            this.messages.push({
                id: data.message.id,
                content: content,  // Original content stored in memory only for this session
                encrypted_content: JSON.stringify(encryptedForRecipient),
                self_encrypted_content: encryptedForSelf ? JSON.stringify(encryptedForSelf) : null,
                created_at: data.message.created_at,
                is_sender: true,
                sender_id: this.userId || currentUserId
            });

            // Render the updated messages
            await this.renderMessages();

            // Clear the textarea
            textarea.value = '';
        } catch (error) {
            console.error('Error sending message:', error);
            alert('Failed to send message: ' + error.message);
        }
    }

    startPolling() {
        // Poll every 5 seconds
        this.pollingInterval = setInterval(() => {
            this.checkNewMessages();
        }, 5000);
    }

    stopPolling() {
        if (this.pollingInterval) {
            clearInterval(this.pollingInterval);
            this.pollingInterval = null;
        }
    }

    async checkNewMessages() {
        try {
            const token = localStorage.getItem('token');
            if (!token) {
                throw new Error('You must be logged in to view messages');
            }

            const response = await fetch(`https://127.0.0.1:5000/api/messages/${this.chatId}/messages`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Accept': 'application/json'
                },
                credentials: 'include'
            });

            if (!response.ok) {
                throw new Error('Failed to check new messages');
            }

            const data = await response.json();
            console.log('Polling received messages:', data);
            
            // Check if there are new messages
            if (data.messages && data.messages.length > this.messages.length) {
                const newMessages = data.messages.slice(this.messages.length);
                this.messages = data.messages.map(msg => ({
                    ...msg,
                    decrypted_content: null // Will be decrypted on demand
                }));
                await this.renderMessages(); // Use the main render method to handle decryption
            }
        } catch (error) {
            console.error('Error checking new messages:', error);
            // Don't show error to user for polling failures
            // this.showError(error.message);
        }
    }

    renderNewMessages(newMessages) {
        const messagesContainer = this.container.querySelector('.chat-messages');
        if (!messagesContainer) return;

        // Add new messages to the container
        for (const message of newMessages) {
            const messageElement = document.createElement('div');
            messageElement.className = `message ${message.is_sender ? 'sent' : 'received'}`;
            
            // Create placeholder for decrypted content
            const contentElement = document.createElement('div');
            contentElement.className = 'message-content loading';
            contentElement.innerHTML = '<p>Decrypting message...</p>';
            messageElement.appendChild(contentElement);
            
            messagesContainer.appendChild(messageElement);
            
            // Decrypt the message asynchronously
            this.decryptMessage(message.encrypted_content, message.sender_id)
                .then(decryptedContent => {
                    contentElement.className = 'message-content';
                    contentElement.innerHTML = `
                        <p>${this.escapeHtml(decryptedContent)}</p>
                        <small>${new Date(message.created_at).toLocaleString()}</small>
                    `;
                })
                .catch(error => {
                    contentElement.className = 'message-content error';
                    contentElement.innerHTML = `
                        <p>Failed to decrypt message</p>
                        <small>${new Date(message.created_at).toLocaleString()}</small>
                    `;
                    console.error('Error decrypting message:', error);
                });
        }

        // Scroll to the bottom
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    // Clean up when leaving the chat
    cleanup() {
        this.stopPolling();
        // Clear sensitive key material
        this.privateKey = null;
        this.otherUserPublicKey = null;
    }

    async loadMessages() {
        try {
            const token = localStorage.getItem('token');
            if (!token) {
                throw new Error('You must be logged in to load messages');
            }

            // Get current user ID from token for verification
            let currentUserId = null;
            try {
                const tokenParts = token.split('.');
                if (tokenParts.length === 3) {
                    const payload = JSON.parse(atob(tokenParts[1]));
                    currentUserId = payload.sub || payload.user_id;
                    console.log('Current user ID from messages:', currentUserId);
                }
            } catch (err) {
                console.error('Error parsing token:', err);
            }

            // Get messages for this chat
            const response = await fetch(`https://127.0.0.1:5000/api/messages/${this.chatId}/messages`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Accept': 'application/json'
                },
                credentials: 'include'
            });

            if (!response.ok) {
                throw new Error('Failed to load messages');
            }

            const data = await response.json();
            console.log('Received messages from server:', data);

            // Process each message to extract both encrypted versions
            const processedMessages = await Promise.all(data.messages.map(async msg => {
                // Check if this is a sent message (by comparing sender_id)
                const isSender = msg.sender_id === currentUserId || msg.is_sender;
                
                // Initialize content to null
                let content = null;
                let recipientEncrypted = null;
                let selfEncrypted = null;
                
                // Try to parse the message payload for both encrypted versions
                try {
                    // Handle different possible formats
                    if (msg.encrypted_content) {
                        try {
                            // Try parsing as a combined payload first (new format)
                            const parsedPayload = JSON.parse(msg.encrypted_content);
                            
                            if (parsedPayload.recipient_encrypted && parsedPayload.self_encrypted) {
                                // This is the new dual-encryption format
                                console.log(`Message ${msg.id} uses dual-encryption format`);
                                recipientEncrypted = parsedPayload.recipient_encrypted;
                                selfEncrypted = parsedPayload.self_encrypted;
                            } else if (isSender && parsedPayload.self_encrypted) {
                                // This has only self-encrypted content
                                console.log(`Message ${msg.id} has only self-encrypted content`);
                                selfEncrypted = parsedPayload.self_encrypted;
                                recipientEncrypted = msg.encrypted_content; // Use the original as fallback
                            } else {
                                // This is a regular encrypted message or another format
                                console.log(`Message ${msg.id} uses regular encryption format`);
                                recipientEncrypted = parsedPayload;
                            }
                        } catch (parseError) {
                            // If parsing fails, it's likely an old format message
                            console.log(`Message ${msg.id} uses old encryption format`);
                            recipientEncrypted = msg.encrypted_content;
                        }
                    }
                } catch (e) {
                    console.error(`Error processing message ${msg.id}:`, e);
                    recipientEncrypted = msg.encrypted_content; // Use original as fallback
                }
                
                console.log(`Processed message ${msg.id}:`, {
                    senderId: msg.sender_id,
                    currentUserId: currentUserId,
                    isSender: isSender,
                    hasRecipientEncrypted: !!recipientEncrypted,
                    hasSelfEncrypted: !!selfEncrypted
                });
                
                return {
                    ...msg,
                    is_sender: isSender,
                    content: null, // No cached content from sessionStorage
                    encrypted_content: recipientEncrypted ? (typeof recipientEncrypted === 'string' ? recipientEncrypted : JSON.stringify(recipientEncrypted)) : msg.encrypted_content,
                    self_encrypted_content: selfEncrypted ? (typeof selfEncrypted === 'string' ? selfEncrypted : JSON.stringify(selfEncrypted)) : null,
                    decrypted_content: null // Will be handled during rendering
                };
            }));

            // Store the processed messages
            this.messages = processedMessages;

            // Render messages
            await this.renderMessages();

        } catch (error) {
            console.error('Error loading messages:', error);
            throw new Error('Failed to load messages');
        }
    }

    render() {
        if (!this.container) {
            console.error('Chat container not found');
            return;
        }

        console.log('Rendering chat UI...');

        // Clear the container first
        this.container.innerHTML = '';

        // Create the chat UI structure
        const chatUI = document.createElement('div');
        chatUI.className = 'chat-container';
        chatUI.innerHTML = `
            <div class="chat-header">
                <h3>${this.escapeHtml(this.inventorName)}</h3>
                <p>Invention: ${this.escapeHtml(this.inventionTitle)}</p>
            </div>
            <div class="chat-messages">
                <div class="loading-messages">
                    <div class="loading-spinner" style="border: 4px solid #dddddd; border-top: 4px solid #ff0000; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin-bottom: 15px;"></div>
                    <p>Loading messages...</p>
                </div>
            </div>
            <div class="chat-input">
                <textarea placeholder="Type your message..." rows="3"></textarea>
                <button class="send-button">Send</button>
            </div>
        `;

        // Add the chat UI to the container
        this.container.appendChild(chatUI);

        // Add CSS for the loading spinner
        if (!document.getElementById('chat-loading-styles')) {
            const style = document.createElement('style');
            style.id = 'chat-loading-styles';
            style.textContent = `
                .loading-messages {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    height: 200px;
                    color: #666;
                }
                
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
                
                .message-content.loading {
                    background-color: #f8f9fc;
                    color: #666;
                }
            `;
            document.head.appendChild(style);
        }

        // Add event listeners
        const sendButton = chatUI.querySelector('.send-button');
        const textarea = chatUI.querySelector('textarea');
        
        console.log('Setting up event listeners...', {
            sendButton: !!sendButton,
            textarea: !!textarea
        });

        if (sendButton && textarea) {
            // Click event for send button
            sendButton.addEventListener('click', () => {
                console.log('Send button clicked');
                const content = textarea.value.trim();
                console.log('Message content:', content);
                if (content) {
                    this.sendMessage(content);
                }
            });
            
            // Enter key event for textarea
            textarea.addEventListener('keypress', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    console.log('Enter key pressed');
                    const content = textarea.value.trim();
                    console.log('Message content:', content);
                    if (content) {
                        this.sendMessage(content);
                    }
                }
            });

            console.log('Event listeners attached successfully');
        } else {
            console.error('Send button or textarea not found in chat UI');
        }
    }

    showError(message) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        errorDiv.textContent = message;
        this.container.appendChild(errorDiv);
        setTimeout(() => errorDiv.remove(), 5000);
    }

    async fetchAndDecryptPrivateKey() {
        try {
            const token = localStorage.getItem('token');
            if (!token) {
                throw new Error('No access token found');
            }

            // Get current user ID from token
            let currentUserId = null;
            try {
                const tokenParts = token.split('.');
                if (tokenParts.length === 3) {
                    const payload = JSON.parse(atob(tokenParts[1]));
                    currentUserId = payload.sub || payload.user_id;
                    console.log('Current user ID from token:', currentUserId);
                }
            } catch (err) {
                console.error('Error parsing token:', err);
            }

            console.log('Fetching private key from server for current user (not the recipient)');
            console.log('Chat details:', {
                chatId: this.chatId,
                otherUserId: this.otherUserId, 
                currentUserId: currentUserId
            });
            
            const response = await fetch('https://127.0.0.1:5000/api/keys/user/me', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            console.log('Response status:', response.status);
            console.log('Response headers:', Object.fromEntries(response.headers.entries()));

            if (!response.ok) {
                throw new Error(`Failed to fetch private key: ${response.statusText}`);
            }

            const data = await response.json();
            console.log('Received key data:', {
                public_key: data.public_key ? 'Present' : 'Missing',
                encrypted_private_key: data.encrypted_private_key ? 'Present' : 'Missing',
                encrypted_private_key_length: data.encrypted_private_key ? data.encrypted_private_key.length : 0
            });

            if (!data.encrypted_private_key) {
                throw new Error('No encrypted private key found in response');
            }

            // Get password hash from localStorage
            const passwordHash = localStorage.getItem('password_hash');
            if (!passwordHash) {
                throw new Error('Password hash not found in localStorage');
            }

            console.log('Starting private key decryption...');
            const privateKey = await CryptoUtils.decryptPrivateKey(data.encrypted_private_key, passwordHash);
            
            // Validate the decrypted private key
            if (!privateKey || privateKey.type !== 'private' || privateKey.algorithm.name !== 'RSA-OAEP') {
                throw new Error('Decrypted private key is invalid');
            }
            
            console.log('Private key successfully decrypted for current user');
            this.privateKey = privateKey;
            return privateKey;
        } catch (error) {
            console.error('Error fetching and decrypting private key:', error);
            throw error;
        }
    }

    async fetchOtherUserPublicKey() {
        try {
            console.log('Fetching public key for recipient user:', this.otherUserId);
            
            if (!this.otherUserId) {
                throw new Error('otherUserId is not set');
            }
            
            // Get current user ID from token
            let currentUserId = null;
            try {
                const tokenParts = this.accessToken.split('.');
                if (tokenParts.length === 3) {
                    const payload = JSON.parse(atob(tokenParts[1]));
                    currentUserId = payload.sub || payload.user_id;
                    console.log('Current user ID from token (sender):', currentUserId);
                }
            } catch (err) {
                console.error('Error parsing token:', err);
            }
            
            console.log('Verifying we are fetching OTHER user public key, not our own:', {
                currentUserId: currentUserId,
                otherUserId: this.otherUserId,
                areDifferent: currentUserId !== this.otherUserId
            });
            
            if (currentUserId === this.otherUserId) {
                console.warn('WARNING: Attempting to fetch public key for self instead of other user!');
            }
            
            const response = await fetch(`https://127.0.0.1:5000/api/keys/user/${this.otherUserId}/public`, {
                headers: {
                    'Authorization': `Bearer ${this.accessToken}`,
                    'Accept': 'application/json'
                },
                credentials: 'include'
            });

            if (!response.ok) {
                throw new Error(`Failed to fetch other user's public key: ${response.status}`);
            }

            const data = await response.json();
            console.log('Received public key data for user ID', this.otherUserId, ':', {
                public_key: data.public_key ? 'Present' : 'Missing',
                public_key_length: data.public_key ? data.public_key.length : 0,
                public_key_first_50: data.public_key ? data.public_key.substring(0, 50) + '...' : 'None',
                public_key_last_50: data.public_key ? '...' + data.public_key.substring(data.public_key.length - 50) : 'None'
            });

            this.otherUserPublicKey = await this.importPublicKey(data.public_key);
            console.log('Successfully imported public key for recipient user:', this.otherUserId);
        } catch (error) {
            console.error('Error fetching other user public key:', error);
            throw error;
        }
    }

    async importPublicKey(pemKey) {
        try {
            console.log('Importing public key:', {
                keyLength: pemKey.length,
                firstChars: pemKey.substring(0, 50) + '...',
                lastChars: '...' + pemKey.substring(pemKey.length - 50)
            });

            // Convert PEM to base64 - properly handle escaped newlines
            const base64Key = pemKey
                .replace('-----BEGIN PUBLIC KEY-----', '')
                .replace('-----END PUBLIC KEY-----', '')
                .replace(/\\n/g, '') // Remove escaped newlines
                .replace(/\n/g, '')  // Remove actual newlines
                .trim();

            console.log('Converted to base64:', {
                length: base64Key.length,
                firstChars: base64Key.substring(0, 20) + '...',
                lastChars: '...' + base64Key.substring(base64Key.length - 20)
            });

            // Compute a checksum of the key for verification
            try {
                const keyData = this.base64ToArrayBuffer(base64Key);
                const keyChecksum = await window.crypto.subtle.digest('SHA-256', keyData);
                const checksumArray = Array.from(new Uint8Array(keyChecksum));
                const checksumHex = checksumArray.map(b => b.toString(16).padStart(2, '0')).join('');
                console.log('Public key checksum (first 16 chars):', checksumHex.substring(0, 16));
            } catch (e) {
                console.error('Error computing key checksum:', e);
            }

            // Import the key
            try {
                const keyBuffer = CryptoUtils.base64ToArrayBuffer(base64Key);
                console.log('Key buffer created:', {
                    byteLength: keyBuffer.byteLength,
                    firstBytes: Array.from(new Uint8Array(keyBuffer.slice(0, 4)))
                });
                
                const key = await window.crypto.subtle.importKey(
                    'spki',
                    keyBuffer,
                    {
                        name: 'RSA-OAEP',
                        hash: 'SHA-256'
                    },
                    true, // Make extractable for debugging
                    ['encrypt']
                );

                console.log('Public key imported successfully:', {
                    type: key.type,
                    algorithm: key.algorithm.name,
                    extractable: key.extractable,
                    usages: key.usages
                });

                return key;
            } catch (importError) {
                console.error('Error importing key:', importError);
                throw importError;
            }
        } catch (error) {
            console.error('Error importing public key:', error);
            console.error('Error details:', {
                name: error.name,
                message: error.message,
                stack: error.stack
            });
            throw error;
        }
    }

    async testEncryptionKeys() {
        try {
            console.log('Testing encryption keys...');
            if (!this.privateKey || !this.otherUserPublicKey) {
                console.error('Keys not available for testing');
                return false;
            }
            
            // Try to test your own keys by encrypting and decrypting test data
            // This requires having both your private and public keys
            try {
                // Get your own public key
                const token = localStorage.getItem('token');
                const response = await fetch('https://127.0.0.1:5000/api/keys/user/me', {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                });
                
                if (!response.ok) {
                    console.error('Could not fetch own public key for testing');
                    return false;
                }
                
                const data = await response.json();
                const myPublicKey = await this.importPublicKey(data.public_key);
                
                // Test encryption/decryption with your own keys
                const testContent = "Test encryption " + new Date().toISOString();
                const encryptedData = await CryptoUtils.encryptMessage(testContent, myPublicKey);
                
                // Now try to decrypt
                try {
                    const decryptedContent = await CryptoUtils.decryptMessage(encryptedData, this.privateKey);
                    console.log('Key test successful!', {
                        originalContent: testContent,
                        decryptedContent: decryptedContent,
                        success: testContent === decryptedContent
                    });
                    return testContent === decryptedContent;
                } catch (e) {
                    console.error('Decryption failed during key test:', e);
                    return false;
                }
            } catch (e) {
                console.error('Could not test keys with own public key:', e);
            }
            
            // As a fallback, just test if the keys are properly formatted
            return (
                this.privateKey && 
                this.privateKey.type === 'private' && 
                this.privateKey.algorithm.name === 'RSA-OAEP' &&
                this.otherUserPublicKey && 
                this.otherUserPublicKey.type === 'public' &&
                this.otherUserPublicKey.algorithm.name === 'RSA-OAEP'
            );
        } catch (error) {
            console.error('Error testing keys:', error);
            return false;
        }
    }
    
    async regenerateAndUploadKeys() {
        console.log('Regenerating keys...');
        try {
            // Remove current keys from localStorage
            localStorage.removeItem('decrypted_private_key');
            
            // Generate new keys
            await this.generateAndUploadKeys();
            
            console.log('Keys regenerated and uploaded successfully');
            return true;
        } catch (error) {
            console.error('Failed to regenerate keys:', error);
            return false;
        }
    }
} 