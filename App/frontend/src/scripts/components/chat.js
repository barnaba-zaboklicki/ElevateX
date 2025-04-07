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
        this.iv = null;
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
            
            // Validate base64 strings
            const validateBase64 = (str) => {
                try {
                    atob(str);
                    return true;
                } catch (e) {
                    return false;
                }
            };

            if (!validateBase64(chatData.raw_key) || !validateBase64(chatData.iv) || 
                !validateBase64(chatData.public_key) || !validateBase64(chatData.private_key)) {
                throw new Error('Invalid base64 encoding in stored data');
            }

            // Import the raw AES key
            const rawKey = Uint8Array.from(atob(chatData.raw_key), c => c.charCodeAt(0));
            console.log('Raw key length:', rawKey.length);
            
            const encryptionKey = await window.crypto.subtle.importKey(
                'raw',
                rawKey,
                { name: 'AES-GCM', length: 256 },
                false,
                ['decrypt']
            );

            const iv = Uint8Array.from(atob(chatData.iv), c => c.charCodeAt(0));
            this.iv = iv;

            // Store the keys
            this.publicKey = chatData.public_key;
            this.privateKey = chatData.private_key;

            console.log('Keys imported successfully');
            
            // Load initial messages
            await this.loadMessages();
            
            // Start polling for new messages
            this.startPolling();
            
            // Render the chat interface
            this.render();
        } catch (error) {
            console.error('Error initializing chat:', error);
            this.showError('Failed to initialize chat encryption');
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
            this.renderMessages();
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

    renderMessages() {
        return this.messages.map(message => `
            <div class="message ${message.sender_id === JSON.parse(localStorage.getItem('user')).id ? 'sent' : 'received'}">
                <div class="message-content">
                    <p>${message.content}</p>
                    <small>${new Date(message.created_at).toLocaleString()}</small>
                </div>
            </div>
        `).join('');
    }

    async sendMessage(content) {
        if (!content.trim() || !this.chatId) return;

        try {
            const token = localStorage.getItem('token');
            if (!token) {
                throw new Error('You must be logged in to send messages');
            }

            console.log('Original message content:', content);

            // Encrypt the message content if we have a public key
            let encryptedContent = content;
            if (this.publicKey) {
                console.log('Public key available, encrypting message...');
                const encoder = new TextEncoder();
                const encodedContent = encoder.encode(content);
                console.log('Encoded content:', encodedContent);
                
                encryptedContent = await window.crypto.subtle.encrypt(
                    { name: 'RSA-OAEP' },
                    this.publicKey,
                    encodedContent
                );
                console.log('Encrypted content (ArrayBuffer):', encryptedContent);
                
                // Convert to base64 for transmission
                encryptedContent = btoa(String.fromCharCode(...new Uint8Array(encryptedContent)));
                console.log('Encrypted content (base64):', encryptedContent);
            } else {
                console.log('No public key available, sending unencrypted message');
            }

            console.log('Sending message to server...');
            const response = await fetch(`https://127.0.0.1:5000/api/messages/${this.chatId}/send`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({ 
                    content: content,
                    encrypted_content: encryptedContent
                }),
                credentials: 'include'
            });

            if (!response.ok) {
                throw new Error('Failed to send message');
            }

            const data = await response.json();
            console.log('Server response:', data);
            
            if (data.message) {
                this.messages.push(data.message);
                this.render();
                
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

    showError(message) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        errorDiv.textContent = message;
        this.container.appendChild(errorDiv);
        setTimeout(() => errorDiv.remove(), 5000);
    }
} 