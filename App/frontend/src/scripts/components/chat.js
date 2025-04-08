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
        try {
            console.log('Initializing chat with data:', {
                chatId,
                inventionId,
                inventorName
            });

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

            // Validate required fields
            if (!chatData.raw_key || !chatData.iv || !chatData.private_key) {
                throw new Error('Missing required encryption data');
            }

            console.log('Processing encryption keys...');
            
            try {
                // Convert base64 to Uint8Array
                const rawKeyArray = Uint8Array.from(atob(chatData.raw_key), c => c.charCodeAt(0));
                const ivArray = Uint8Array.from(atob(chatData.iv), c => c.charCodeAt(0));
                const encryptedPrivateKeyArray = Uint8Array.from(atob(chatData.private_key), c => c.charCodeAt(0));

                console.log('Key lengths:', {
                    rawKey: rawKeyArray.length,
                    iv: ivArray.length,
                    encryptedPrivateKey: encryptedPrivateKeyArray.length
                });

                // Import the AES key
                const aesKey = await window.crypto.subtle.importKey(
                    'raw',
                    rawKeyArray,
                    { name: 'AES-GCM', length: 256 },
                    false,
                    ['decrypt']
                );

                console.log('AES key imported successfully');

                // Decrypt the private key
                const decryptedPrivateKey = await window.crypto.subtle.decrypt(
                    { 
                        name: 'AES-GCM', 
                        iv: ivArray 
                    },
                    aesKey,
                    encryptedPrivateKeyArray
                );

                console.log('Private key decrypted successfully');

                // Log the decrypted key length
                console.log('Decrypted private key length:', decryptedPrivateKey.byteLength);

                try {
                    // Convert decrypted key to string to check format
                    const keyString = new TextDecoder().decode(decryptedPrivateKey);
                    console.log('Key format check:', keyString.substring(0, 50));

                    let keyData;
                    
                    // The key is in base64 PKCS#8 format
                    try {
                        // Convert base64 string to binary
                        keyData = Uint8Array.from(atob(keyString), c => c.charCodeAt(0));
                        console.log('Converted base64 to binary, new length:', keyData.byteLength);
                    } catch (e) {
                        console.error('Error converting base64:', e);
                        // If base64 conversion fails, try using the decrypted key directly
                        keyData = new Uint8Array(decryptedPrivateKey);
                    }

                    // Import the private key
                    this.privateKey = await window.crypto.subtle.importKey(
                        'pkcs8',
                        keyData.buffer,
                        {
                            name: 'RSA-OAEP',
                            hash: 'SHA-256'
                        },
                        true,
                        ['decrypt']
                    );

                    console.log('Private key imported successfully');
                } catch (importError) {
                    console.error('Error importing private key:', importError);
                    
                    // Try to diagnose the key format
                    const keyView = new Uint8Array(decryptedPrivateKey);
                    console.log('First few bytes of decrypted key:', 
                        Array.from(keyView.slice(0, 16))
                            .map(b => b.toString(16).padStart(2, '0'))
                            .join(' ')
                    );
                    
                    // If we can decode it as text, show the start of the key
                    try {
                        const keyText = new TextDecoder().decode(decryptedPrivateKey);
                        console.log('Key as text (first 100 chars):', keyText.substring(0, 100));
                    } catch (e) {
                        console.log('Key could not be decoded as text');
                    }
                    
                    throw new Error(`Failed to import private key: ${importError.message}`);
                }

                // Load messages and start polling
                await this.loadMessages();
                this.startPolling();
                
                console.log('Chat initialized successfully');
            } catch (e) {
                console.error('Error processing encryption keys:', e);
                throw new Error(`Failed to process encryption keys: ${e.message}`);
            }
        } catch (error) {
            console.error('Error initializing chat:', error);
            this.showError(`Failed to initialize chat: ${error.message}`);
            throw error;
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

    async decryptMessage(encryptedContent) {
        try {
            if (!this.privateKey) {
                throw new Error('Private key not available for decryption');
            }

            // Decode the base64 encrypted content
            const encryptedBytes = Uint8Array.from(atob(encryptedContent), c => c.charCodeAt(0));

            // Decrypt the content
            const decryptedBytes = await window.crypto.subtle.decrypt(
                { name: 'RSA-OAEP' },
                this.privateKey,
                encryptedBytes
            );

            // Convert decrypted bytes to text
            return new TextDecoder().decode(decryptedBytes);
        } catch (error) {
            console.error('Error decrypting message:', error);
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

            // Encrypt the message
            const encoder = new TextEncoder();
            const encodedContent = encoder.encode(content);
            const encryptedContent = await window.crypto.subtle.encrypt(
                { name: 'RSA-OAEP' },
                this.otherUserPublicKey,
                encodedContent
            );

            // Convert to base64 for transmission
            const encryptedBase64 = btoa(String.fromCharCode(...new Uint8Array(encryptedContent)));

            // Send only the encrypted content to the server
            const response = await fetch(`https://127.0.0.1:5000/api/messages/${this.chatId}/send`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({ 
                    encrypted_content: encryptedBase64
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
                    encrypted_content: encryptedBase64,
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