class Chat {
    constructor(containerId) {
        this.containerId = containerId;
        this.container = document.getElementById(containerId);
        this.inventorName = '';
        this.inventionTitle = '';
        this.chatId = '';
        this.messages = [];
        this.publicKey = null;
        this.privateKey = null;
        this.otherUserPublicKey = null;
        this.pollingInterval = null;
        this.lastMessageId = null;
    }

    async initialize(inventionId, inventorName, chatId) {
        this.inventorName = inventorName;
        this.inventionTitle = inventionId;
        this.chatId = chatId;
        
        // Get encryption keys from sessionStorage
        const chatKey = `chat_keys_${chatId}`;
        const chatData = JSON.parse(sessionStorage.getItem(chatKey));
        
        if (!chatData) {
            console.error('No chat data found for key:', chatKey);
            this.showError('Chat data not found. Please try starting the chat again.');
            return;
        }

        try {
            console.log('Found chat data:', chatData);
            
            // Import the keys for decryption
            const privateKeyBytes = await this.decryptStoredKey(chatData.private_key, chatData.raw_key, chatData.iv);
            this.privateKey = await window.crypto.subtle.importKey(
                'pkcs8',
                privateKeyBytes,
                {
                    name: 'RSA-OAEP',
                    hash: 'SHA-256'
                },
                true,
                ['decrypt']
            );

            // Load messages and other user's public key
            await this.loadMessages();
            
            // Start polling for new messages
            this.startPolling();
            
            console.log('Chat initialized successfully');
        } catch (error) {
            console.error('Error initializing chat:', error);
            this.showError('Failed to initialize chat encryption');
        }
    }

    async decryptStoredKey(encryptedKeyBase64, rawKeyBase64, ivBase64) {
        // Decode the base64 strings
        const encryptedKey = Uint8Array.from(atob(encryptedKeyBase64), c => c.charCodeAt(0));
        const rawKey = Uint8Array.from(atob(rawKeyBase64), c => c.charCodeAt(0));
        const iv = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));

        // Import the raw AES key
        const aesKey = await window.crypto.subtle.importKey(
            'raw',
            rawKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );

        // Decrypt the key
        const decryptedKey = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            aesKey,
            encryptedKey
        );

        return decryptedKey;
    }

    async decryptMessage(encryptedContent, isSender) {
        try {
            // If this is a message we sent, we can't decrypt it (it was encrypted with the recipient's public key)
            if (isSender) {
                return '[Message sent - encrypted with recipient\'s key]';
            }

            if (!this.privateKey) {
                throw new Error('Private key not available for decryption');
            }

            // Log the private key details before attempting decryption
            try {
                const keyInfo = await window.crypto.subtle.exportKey('jwk', this.privateKey);
                console.log('Private key info before decryption:', {
                    keyType: keyInfo.kty,
                    algorithm: keyInfo.alg,
                    keySize: keyInfo.n ? Math.ceil((keyInfo.n.length * 6) / 8) * 8 : 'unknown',
                    modulusLength: keyInfo.n ? (keyInfo.n.length * 6) : 'unknown'
                });
            } catch (keyError) {
                console.error('Error getting key info:', keyError);
            }

            try {
                // Try to parse as JSON first (new format)
                const messageData = JSON.parse(encryptedContent);
                console.log('Message format:', messageData);
                
                if (messageData.encryptedKey && messageData.encryptedData && messageData.iv) {
                    console.log('Decrypting message in new format');
                    
                    const encryptedKeyBytes = Uint8Array.from(atob(messageData.encryptedKey), c => c.charCodeAt(0));
                    const encryptedDataBytes = Uint8Array.from(atob(messageData.encryptedData), c => c.charCodeAt(0));
                    const ivBytes = Uint8Array.from(atob(messageData.iv), c => c.charCodeAt(0));

                    console.log('Encrypted data lengths:', {
                        key: encryptedKeyBytes.length,
                        data: encryptedDataBytes.length,
                        iv: ivBytes.length
                    });

                    // First decrypt the AES key using RSA
                    const decryptedKeyBytes = await window.crypto.subtle.decrypt(
                        { 
                            name: 'RSA-OAEP',
                            hash: { name: 'SHA-256' }
                        },
                        this.privateKey,
                        encryptedKeyBytes
                    );

                    console.log('AES key decrypted successfully, length:', decryptedKeyBytes.byteLength);

                    // Import the decrypted AES key
                    const aesKey = await window.crypto.subtle.importKey(
                        'raw',
                        decryptedKeyBytes,
                        { name: 'AES-GCM', length: 256 },
                        false,
                        ['decrypt']
                    );

                    console.log('AES key imported successfully');

                    // Use the AES key to decrypt the actual message
                    const decryptedBytes = await window.crypto.subtle.decrypt(
                        { name: 'AES-GCM', iv: ivBytes },
                        aesKey,
                        encryptedDataBytes
                    );

                    console.log('Message decrypted successfully, length:', decryptedBytes.byteLength);

                    // Convert decrypted bytes to text
                    return new TextDecoder().decode(decryptedBytes);
                } else {
                    throw new Error('Invalid message format');
                }
            } catch (jsonError) {
                // If JSON parsing fails or message format is invalid, try the old format
                console.log('Falling back to old message format');
                console.log('JSON parse error:', jsonError);
                
                try {
                    // Convert base64 to Uint8Array
                    const encryptedBytes = Uint8Array.from(atob(encryptedContent), c => c.charCodeAt(0));
                    console.log('Encrypted bytes length:', encryptedBytes.length);
                    
                    // Log the first few bytes for debugging
                    console.log('First few bytes:', Array.from(encryptedBytes.slice(0, 16))
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join(' '));

                    // Try to decrypt with RSA-OAEP with explicit hash
                    const decryptedBytes = await window.crypto.subtle.decrypt(
                        { 
                            name: 'RSA-OAEP',
                            hash: { name: 'SHA-256' }
                        },
                        this.privateKey,
                        encryptedBytes
                    ).catch(error => {
                        console.error('RSA decryption failed:', error);
                        throw error;
                    });
                    
                    console.log('Decrypted bytes length:', decryptedBytes.byteLength);
                    
                    // Convert decrypted bytes to text
                    const decryptedText = new TextDecoder().decode(decryptedBytes);
                    console.log('Decrypted text length:', decryptedText.length);
                    
                    return decryptedText;
                } catch (decryptError) {
                    console.error('RSA decryption error:', decryptError);
                    console.error('Error details:', {
                        name: decryptError.name,
                        message: decryptError.message,
                        stack: decryptError.stack
                    });

                    // Log key information
                    try {
                        const keyInfo = await window.crypto.subtle.exportKey('jwk', this.privateKey);
                        console.log('Private key info during failed decryption:', {
                            keyType: keyInfo.kty,
                            algorithm: keyInfo.alg,
                            keySize: keyInfo.n ? Math.ceil((keyInfo.n.length * 6) / 8) * 8 : 'unknown',
                            modulusLength: keyInfo.n ? (keyInfo.n.length * 6) : 'unknown'
                        });
                    } catch (keyError) {
                        console.error('Error getting key info:', keyError);
                    }

                    throw decryptError;
                }
            }
        } catch (error) {
            console.error('Error decrypting message:', error);
            console.error('Error details:', {
                name: error.name,
                message: error.message,
                stack: error.stack
            });
            return '[Unable to decrypt message]';
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
            const token = localStorage.getItem('token');
            if (!token) {
                throw new Error('You must be logged in to send messages');
            }

            // Get the other user's public key if we don't have it
            if (!this.otherUserPublicKey) {
                const response = await fetch(`https://127.0.0.1:5000/api/messages/${this.chatId}`, {
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Accept': 'application/json'
                    },
                    credentials: 'include'
                });

                if (!response.ok) {
                    throw new Error('Failed to get recipient public key');
                }

                const data = await response.json();
                const publicKeyBytes = Uint8Array.from(atob(data.other_user.public_key), c => c.charCodeAt(0));
                this.otherUserPublicKey = await window.crypto.subtle.importKey(
                    'spki',
                    publicKeyBytes,
                    {
                        name: 'RSA-OAEP',
                        hash: 'SHA-256'
                    },
                    true,
                    ['encrypt']
                );
            }

            // Generate a random AES key for this message
            const aesKey = await window.crypto.subtle.generateKey(
                { name: 'AES-GCM', length: 256 },
                true,
                ['encrypt']
            );

            // Generate IV for AES encryption
            const iv = window.crypto.getRandomValues(new Uint8Array(12));

            // Export the AES key
            const rawAesKey = await window.crypto.subtle.exportKey('raw', aesKey);

            // Encrypt the AES key with recipient's public key
            const encryptedAesKey = await window.crypto.subtle.encrypt(
                { 
                    name: 'RSA-OAEP',
                    hash: { name: 'SHA-256' }
                },
                this.otherUserPublicKey,
                rawAesKey
            );

            // Encrypt the actual message with AES
            const encoder = new TextEncoder();
            const encodedContent = encoder.encode(content);
            const encryptedContent = await window.crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                aesKey,
                encodedContent
            );

            // Convert everything to base64
            const encryptedKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(encryptedAesKey)));
            const encryptedDataBase64 = btoa(String.fromCharCode(...new Uint8Array(encryptedContent)));
            const ivBase64 = btoa(String.fromCharCode(...iv));

            // Create the message object
            const messageObject = {
                encryptedKey: encryptedKeyBase64,
                encryptedData: encryptedDataBase64,
                iv: ivBase64
            };

            // Send the encrypted message to the server
            const response = await fetch(`https://127.0.0.1:5000/api/messages/${this.chatId}/send`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({ 
                    encrypted_content: JSON.stringify(messageObject)
                }),
                credentials: 'include'
            });

            if (!response.ok) {
                throw new Error('Failed to send message');
            }

            const data = await response.json();
            
            if (data.message) {
                // Add the message to our local list with the encrypted content
                this.messages.push({
                    ...data.message,
                    encrypted_content: JSON.stringify(messageObject),
                    is_sender: true
                });
                await this.renderMessages();
                
                // Clear the input
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

            const response = await fetch(`https://127.0.0.1:5000/api/messages/${this.chatId}`, {
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
            
            // Check if there are new messages
            if (data.messages.length > this.messages.length) {
                const newMessages = data.messages.slice(this.messages.length);
                this.messages = data.messages;
                this.renderNewMessages(newMessages);
            }
        } catch (error) {
            console.error('Error checking new messages:', error);
        }
    }

    renderNewMessages(newMessages) {
        const messagesContainer = this.container.querySelector('.chat-messages');
        if (!messagesContainer) return;

        // Add new messages to the container
        newMessages.forEach(message => {
            const messageElement = document.createElement('div');
            messageElement.className = `message ${message.is_sender ? 'sent' : 'received'}`;
            messageElement.innerHTML = `
                <div class="message-content">
                    <p>${message.content}</p>
                    <small>${new Date(message.created_at).toLocaleString()}</small>
                </div>
            `;
            messagesContainer.appendChild(messageElement);
        });

        // Scroll to the bottom
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    // Clean up when leaving the chat
    cleanup() {
        this.stopPolling();
    }

    async loadMessages() {
        try {
            const token = localStorage.getItem('token');
            if (!token) {
                throw new Error('You must be logged in to view messages');
            }

            const response = await fetch(`https://127.0.0.1:5000/api/messages/${this.chatId}`, {
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
            this.messages = data.messages;
            await this.renderMessages();
        } catch (error) {
            console.error('Error loading messages:', error);
            this.showError(error.message);
        }
    }

    render() {
        if (!this.container) {
            console.error('Chat container not found');
            return;
        }

        this.container.innerHTML = `
            <div class="chat-container">
                <div class="chat-messages">
                    ${this.messages.length > 0 ? this.renderMessages() : '<div class="no-messages">No messages yet</div>'}
                </div>
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
            sendButton.addEventListener('click', () => this.sendMessage(textarea.value));
            textarea.addEventListener('keypress', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    this.sendMessage(textarea.value);
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
} 