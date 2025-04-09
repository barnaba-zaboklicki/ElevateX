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
        // Generate a random AES key for message encryption
        const aesKey = await window.crypto.subtle.generateKey(
            {
                name: 'AES-GCM',
                length: 256
            },
            true,
            ['encrypt']
        );

        // Export the AES key
        const exportedAesKey = await window.crypto.subtle.exportKey('raw', aesKey);

        // Encrypt the AES key with RSA
        const encryptedKey = await window.crypto.subtle.encrypt(
            {
                name: 'RSA-OAEP'
            },
            publicKey,
            exportedAesKey
        );

        // Encrypt the message with AES
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encryptedContent = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            aesKey,
            new TextEncoder().encode(content)
        );

        return {
            encrypted_key: this.arrayBufferToBase64(encryptedKey),
            encrypted_content: this.arrayBufferToBase64(encryptedContent),
            iv: this.arrayBufferToBase64(iv)
        };
    }

    static async decryptMessage(encryptedData, privateKey) {
        // Decrypt the AES key
        const decryptedKey = await window.crypto.subtle.decrypt(
            {
                name: 'RSA-OAEP'
            },
            privateKey,
            this.base64ToArrayBuffer(encryptedData.encrypted_key)
        );

        // Import the decrypted AES key
        const aesKey = await window.crypto.subtle.importKey(
            'raw',
            decryptedKey,
            {
                name: 'AES-GCM',
                length: 256
            },
            true,
            ['decrypt']
        );

        // Decrypt the message
        const decryptedContent = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: this.base64ToArrayBuffer(encryptedData.iv)
            },
            aesKey,
            this.base64ToArrayBuffer(encryptedData.encrypted_content)
        );

        return new TextDecoder().decode(decryptedContent);
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
            console.log('Starting decryption with:', {
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

            // Import the decrypted private key as PEM
            const privateKey = await window.crypto.subtle.importKey(
                'pkcs8',
                this.base64ToArrayBuffer(pemString.split('-----')[2].trim()),
                {
                    name: 'RSA-OAEP',
                    hash: 'SHA-256'
                },
                false,
                ['decrypt']
            );
            console.log('Private key imported successfully');

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
            
            // Fetch and decrypt the private key
            await this.fetchAndDecryptPrivateKey();
            
            // Fetch the other user's public key
            await this.fetchOtherUserPublicKey();
            
            // Load messages
            await this.loadMessages();
            
            // Start polling for new messages
            this.startPolling();
            
            this.initialized = true;
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

        // Render each message
        for (const message of this.messages) {
            const decryptedContent = await this.decryptMessage(message.encrypted_content);
            const messageElement = document.createElement('div');
            messageElement.className = `message ${message.is_sender ? 'sent' : 'received'}`;
            messageElement.innerHTML = `
                <div class="message-content">
                    <p>${this.escapeHtml(decryptedContent)}</p>
                    <small>${new Date(message.created_at).toLocaleString()}</small>
                </div>
            `;
            messagesContainer.appendChild(messageElement);
        }

        // Scroll to bottom
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    async sendMessage(content) {
        if (!content.trim() || !this.chatId) return;

        try {
            if (!this.initialized || !this.otherUserPublicKey) {
                throw new Error('Chat not properly initialized');
            }

            // Encrypt the message
            const encryptedData = await CryptoUtils.encryptMessage(content, this.otherUserPublicKey);

            // Send the encrypted message
            const response = await fetch(`https://127.0.0.1:5000/api/messages/${this.chatId}/send`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + localStorage.getItem('access_token')
                },
                body: JSON.stringify({
                    encrypted_content: JSON.stringify(encryptedData)
                })
            });

            if (!response.ok) {
                throw new Error('Failed to send message');
            }

            const data = await response.json();
            
            if (data.message) {
                this.messages.push({
                    ...data.message,
                    encrypted_content: JSON.stringify(encryptedData),
                    is_sender: true
                });
                await this.renderMessages();
                
                const textarea = this.container.querySelector('textarea');
                if (textarea) {
                    textarea.value = '';
                }
            } else {
                throw new Error('Invalid response format');
            }
        } catch (error) {
            console.error('Error sending message:', error);
            this.showError(error.message);
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
            console.log('Received messages:', data);

            // Store messages
            this.messages = data.messages.map(msg => ({
                ...msg,
                decrypted_content: null // Will be decrypted on demand
            }));

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

        this.container.innerHTML = `
            <div class="chat-container">
                <div class="chat-header">
                    <h3>${this.escapeHtml(this.inventorName)}</h3>
                    <p>Invention: ${this.escapeHtml(this.inventionTitle)}</p>
                </div>
                <div class="chat-messages"></div>
                <div class="chat-input">
                    <textarea placeholder="Type your message..." rows="3"></textarea>
                    <button class="send-button">Send</button>
                </div>
            </div>
        `;

        // Add event listeners
        const sendButton = this.container.querySelector('.send-button');
        const textarea = this.container.querySelector('textarea');
        
        if (sendButton && textarea) {
            sendButton.addEventListener('click', () => {
                const content = textarea.value.trim();
                if (content) {
                    this.sendMessage(content);
                }
            });
            
            textarea.addEventListener('keypress', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    const content = textarea.value.trim();
                    if (content) {
                        this.sendMessage(content);
                    }
                }
            });
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

            console.log('Fetching private key from server...');
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
                encrypted_private_key_length: data.encrypted_private_key ? data.encrypted_private_key.length : 0,
                encrypted_private_key_first_50: data.encrypted_private_key ? data.encrypted_private_key.substring(0, 50) + '...' : 'None',
                encrypted_private_key_last_50: data.encrypted_private_key ? '...' + data.encrypted_private_key.substring(data.encrypted_private_key.length - 50) : 'None'
            });

            if (!data.encrypted_private_key) {
                throw new Error('No encrypted private key found in response');
            }

            // Decrypt the private key using the password hash
            this.privateKey = await CryptoUtils.decryptPrivateKey(data.encrypted_private_key, localStorage.getItem('password_hash'));
            console.log('Successfully decrypted and imported private key');
        } catch (error) {
            console.error('Error fetching private key:', error);
            throw error;
        }
    }

    async fetchOtherUserPublicKey() {
        try {
            console.log('Fetching public key for user:', this.otherUserId);
            
            if (!this.otherUserId) {
                throw new Error('otherUserId is not set');
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
            console.log('Received public key data:', {
                public_key: data.public_key,
                public_key_length: data.public_key ? data.public_key.length : 0,
                public_key_first_50: data.public_key ? data.public_key.substring(0, 50) + '...' : 'None',
                public_key_last_50: data.public_key ? '...' + data.public_key.substring(data.public_key.length - 50) : 'None'
            });

            this.otherUserPublicKey = await this.importPublicKey(data.public_key);
            console.log('Successfully imported other user public key');
        } catch (error) {
            console.error('Error fetching other user public key:', error);
            throw error;
        }
    }

    async importPublicKey(pemKey) {
        try {
            // Convert PEM to base64
            const base64Key = pemKey
                .replace('-----BEGIN PUBLIC KEY-----', '')
                .replace('-----END PUBLIC KEY-----', '')
                .replace(/\n/g, '')
                .trim();

            // Import the key
            const key = await CryptoUtils.importKey(
                base64Key,
                'spki',
                'public',
                ['encrypt']
            );

            return key;
        } catch (error) {
            console.error('Error importing public key:', error);
            throw error;
        }
    }
} 