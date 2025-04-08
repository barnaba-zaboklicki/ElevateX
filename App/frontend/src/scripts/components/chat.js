class Chat {
    constructor(containerId) {
        this.containerId = containerId;
        this.container = document.getElementById(containerId);
        this.inventorName = '';
        this.inventionTitle = '';
        this.chatId = '';
        this.messages = [];
        
        // Signal Protocol state
        this.registrationId = null;
        this.identityKeyPair = null;
        this.signingKeyPair = null;  // New: separate key pair for signing
        this.signedPreKeyPair = null;
        this.oneTimePreKeys = [];
        this.sessions = new Map();
        
        this.pollingInterval = null;
        this.lastMessageId = null;
    }

    async initialize(inventionId, inventorName, chatId) {
        this.inventorName = inventorName;
        this.inventionTitle = inventionId;
        this.chatId = chatId;
        
        try {
            // Initialize Signal Protocol
            await this.initializeSignalProtocol();
            
            // Render the chat interface first
            this.render();
            
            // Load messages
            await this.loadMessages();
            
            // Start polling for new messages
            this.startPolling();
            
            console.log('Chat initialized successfully');
        } catch (error) {
            console.error('Error initializing chat:', error);
            this.showError('Failed to initialize chat encryption');
        }
    }

    async initializeSignalProtocol() {
        // Generate or load registration ID
        this.registrationId = parseInt(localStorage.getItem(`signal_reg_id_${this.chatId}`)) || 
            Math.floor(Math.random() * 16384);
        localStorage.setItem(`signal_reg_id_${this.chatId}`, this.registrationId.toString());

        // Generate or load identity key pair for ECDH
        const storedIdentityKey = localStorage.getItem(`signal_identity_key_${this.chatId}`);
        if (storedIdentityKey) {
            this.identityKeyPair = await this.importKeyPair(JSON.parse(storedIdentityKey), 'ECDH');
        } else {
            this.identityKeyPair = await this.generateKeyPair('ECDH');
            localStorage.setItem(`signal_identity_key_${this.chatId}`, 
                JSON.stringify(await this.exportKeyPair(this.identityKeyPair)));
        }

        // Generate or load signing key pair
        const storedSigningKey = localStorage.getItem(`signal_signing_key_${this.chatId}`);
        if (storedSigningKey) {
            this.signingKeyPair = await this.importKeyPair(JSON.parse(storedSigningKey), 'ECDSA');
        } else {
            this.signingKeyPair = await this.generateKeyPair('ECDSA');
            localStorage.setItem(`signal_signing_key_${this.chatId}`, 
                JSON.stringify(await this.exportKeyPair(this.signingKeyPair)));
        }

        // Generate signed pre-key
        this.signedPreKeyPair = await this.generateKeyPair('ECDH');
        const signature = await this.signPreKey(this.signedPreKeyPair.publicKey);

        // Generate one-time pre-keys
        this.oneTimePreKeys = [];
        for (let i = 0; i < 20; i++) {
            this.oneTimePreKeys.push(await this.generateKeyPair('ECDH'));
        }

        // Upload key bundle to server
        await this.uploadKeyBundle();
    }

    async generateKeyPair(algorithm) {
        const params = algorithm === 'ECDH' ? 
            {
                name: 'ECDH',
                namedCurve: 'P-256'
            } : 
            {
                name: 'ECDSA',
                namedCurve: 'P-256'
            };

        const usages = algorithm === 'ECDH' ? 
            ['deriveKey', 'deriveBits'] : 
            ['sign', 'verify'];

        return await window.crypto.subtle.generateKey(
            params,
            true,
            usages
        );
    }

    async importKeyPair(serializedKeyPair, algorithm) {
        const publicKeyBuffer = this.base64ToArrayBuffer(serializedKeyPair.publicKey);
        const privateKeyBuffer = this.base64ToArrayBuffer(serializedKeyPair.privateKey);

        const params = algorithm === 'ECDH' ? 
            {
                name: 'ECDH',
                namedCurve: 'P-256'
            } : 
            {
                name: 'ECDSA',
                namedCurve: 'P-256'
            };

        const publicKeyUsages = algorithm === 'ECDH' ? [] : ['verify'];
        const privateKeyUsages = algorithm === 'ECDH' ? ['deriveKey', 'deriveBits'] : ['sign'];

        const publicKey = await window.crypto.subtle.importKey(
            'raw',
            publicKeyBuffer,
            params,
            true,
            publicKeyUsages
        );

        const privateKey = await window.crypto.subtle.importKey(
            'pkcs8',
            privateKeyBuffer,
            params,
            true,
            privateKeyUsages
        );

        return { publicKey, privateKey };
    }

    async signPreKey(preKey) {
        const preKeyBytes = await window.crypto.subtle.exportKey('raw', preKey);
        const signature = await window.crypto.subtle.sign(
            {
                name: 'ECDSA',
                hash: { name: 'SHA-256' }
            },
            this.signingKeyPair.privateKey,
            preKeyBytes
        );
        return signature;
    }

    async establishSession(otherUserId, theirKeyBundle) {
        // X3DH key agreement
        const sharedSecret = await this.performX3DH(theirKeyBundle);
        
        // Initialize Double Ratchet
        const session = {
            rootKey: await this.deriveRootKey(sharedSecret),
            sendingChain: await this.initializeChain(),
            receivingChain: await this.initializeChain(),
            messageKeys: new Map()
        };

        this.sessions.set(otherUserId, session);
        return session;
    }

    async performX3DH(theirKeyBundle) {
        const dh1 = await this.deriveSharedSecret(
            this.identityKeyPair.privateKey,
            theirKeyBundle.identityKey
        );
        const dh2 = await this.deriveSharedSecret(
            this.identityKeyPair.privateKey,
            theirKeyBundle.signedPreKey
        );
        const dh3 = await this.deriveSharedSecret(
            this.signedPreKeyPair.privateKey,
            theirKeyBundle.identityKey
        );

        // Combine shared secrets using HKDF
        return await this.hkdf(
            new Uint8Array([...dh1, ...dh2, ...dh3]),
            'X3DH'
        );
    }

    async deriveSharedSecret(privateKey, publicKey) {
        return await window.crypto.subtle.deriveBits(
            {
                name: 'ECDH',
                public: publicKey
            },
            privateKey,
            256
        );
    }

    async hkdf(input, salt) {
        const key = await window.crypto.subtle.importKey(
            'raw',
            input,
            { name: 'HKDF' },
            false,
            ['deriveBits']
        );

        return await window.crypto.subtle.deriveBits(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: new TextEncoder().encode(salt),
                info: new Uint8Array(0)
            },
            key,
            256
        );
    }

    async encryptMessage(content, recipientId) {
        let session = this.sessions.get(recipientId);
        if (!session) {
            const keyBundle = await this.fetchKeyBundle(recipientId);
            session = await this.establishSession(recipientId, keyBundle);
        }

        // Generate message key
        const messageKey = await this.deriveMessageKey(session.sendingChain);
        
        // Encrypt message content
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encryptedContent = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            messageKey,
            new TextEncoder().encode(content)
        );

        // Update ratchet
        session.sendingChain = await this.ratchetChain(session.sendingChain);

        return {
            header: {
                ephemeralKey: session.sendingChain.publicKey,
                counter: session.sendingChain.counter,
                previousCounter: session.sendingChain.previousCounter
            },
            iv: iv,
            ciphertext: encryptedContent
        };
    }

    async decryptMessage(encryptedMessage, senderId) {
        let session = this.sessions.get(senderId);
        if (!session) {
            throw new Error('No session established with sender');
        }

        // Derive message key
        const messageKey = await this.deriveMessageKey(session.receivingChain);

        // Decrypt message
        const decryptedContent = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: encryptedMessage.iv },
            messageKey,
            encryptedMessage.ciphertext
        );

        // Update ratchet
        session.receivingChain = await this.ratchetChain(session.receivingChain);

        return new TextDecoder().decode(decryptedContent);
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
            const token = localStorage.getItem('token');
            if (!token) {
                throw new Error('You must be logged in to send messages');
            }

            // Encrypt message using Signal Protocol
            const encryptedMessage = await this.encryptMessage(content, this.chatId);

            // Send the encrypted message to the server
            const response = await fetch(`https://127.0.0.1:5000/api/messages/${this.chatId}/send`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({ 
                    encrypted_content: JSON.stringify(encryptedMessage)
                }),
                credentials: 'include'
            });

            if (!response.ok) {
                throw new Error('Failed to send message');
            }

            const data = await response.json();
            
            if (data.message) {
                this.messages.push({
                    ...data.message,
                    encrypted_content: JSON.stringify(encryptedMessage),
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
        this.identityKeyPair = null;
        this.signingKeyPair = null;
        this.signedPreKeyPair = null;
        this.oneTimePreKeys = [];
        this.sessions.clear();
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

    async exportKeyPair(keyPair) {
        const publicKey = await window.crypto.subtle.exportKey('raw', keyPair.publicKey);
        const privateKey = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
        
        return {
            publicKey: this.arrayBufferToBase64(publicKey),
            privateKey: this.arrayBufferToBase64(privateKey)
        };
    }

    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    async uploadKeyBundle() {
        try {
            const token = localStorage.getItem('token');
            if (!token) {
                throw new Error('You must be logged in to upload keys');
            }

            // Export public keys for the bundle
            const identityPublicKey = await window.crypto.subtle.exportKey('raw', this.identityKeyPair.publicKey);
            const signedPrePublicKey = await window.crypto.subtle.exportKey('raw', this.signedPreKeyPair.publicKey);
            const signature = await this.signPreKey(this.signedPreKeyPair.publicKey);

            // Export one-time pre-key public keys
            const oneTimePreKeyPublics = await Promise.all(
                this.oneTimePreKeys.map(async (keyPair) => {
                    const publicKey = await window.crypto.subtle.exportKey('raw', keyPair.publicKey);
                    return this.arrayBufferToBase64(publicKey);
                })
            );

            // Prepare the key bundle
            const keyBundle = {
                registration_id: this.registrationId,
                identity_key: this.arrayBufferToBase64(identityPublicKey),
                signed_pre_key: this.arrayBufferToBase64(signedPrePublicKey),
                signature: this.arrayBufferToBase64(signature),
                one_time_pre_keys: oneTimePreKeyPublics
            };

            console.log('Uploading key bundle for chat:', this.chatId);

            // Upload to server
            const response = await fetch(`https://127.0.0.1:5000/api/keys/${this.chatId}/upload`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify(keyBundle),
                credentials: 'include'
            });

            if (!response.ok) {
                const errorData = await response.json();
                console.error('Key bundle upload failed:', errorData);
                throw new Error(errorData.message || 'Failed to upload key bundle');
            }

            console.log('Key bundle uploaded successfully');
            return await response.json();
        } catch (error) {
            console.error('Error uploading key bundle:', error);
            throw new Error('Failed to initialize encryption: ' + error.message);
        }
    }

    async fetchKeyBundle(userId) {
        try {
            const token = localStorage.getItem('token');
            if (!token) {
                throw new Error('You must be logged in to fetch keys');
            }

            const response = await fetch(`https://127.0.0.1:5000/api/keys/${userId}/bundle`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Accept': 'application/json'
                },
                credentials: 'include'
            });

            if (!response.ok) {
                throw new Error('Failed to fetch key bundle');
            }

            const bundle = await response.json();

            // Convert base64 keys back to CryptoKey objects
            return {
                registrationId: bundle.registration_id,
                identityKey: await window.crypto.subtle.importKey(
                    'raw',
                    this.base64ToArrayBuffer(bundle.identity_key),
                    { name: 'ECDH', namedCurve: 'P-256' },
                    true,
                    []
                ),
                signedPreKey: await window.crypto.subtle.importKey(
                    'raw',
                    this.base64ToArrayBuffer(bundle.signed_pre_key),
                    { name: 'ECDH', namedCurve: 'P-256' },
                    true,
                    []
                ),
                signature: this.base64ToArrayBuffer(bundle.signature),
                oneTimePreKey: bundle.one_time_pre_key ? await window.crypto.subtle.importKey(
                    'raw',
                    this.base64ToArrayBuffer(bundle.one_time_pre_key),
                    { name: 'ECDH', namedCurve: 'P-256' },
                    true,
                    []
                ) : null
            };
        } catch (error) {
            console.error('Error fetching key bundle:', error);
            throw new Error('Failed to establish secure connection: ' + error.message);
        }
    }
} 