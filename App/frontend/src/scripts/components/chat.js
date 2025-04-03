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

            // Decrypt the keys
            const encryptedPublicKey = Uint8Array.from(atob(chatData.public_key), c => c.charCodeAt(0));
            const encryptedPrivateKey = Uint8Array.from(atob(chatData.private_key), c => c.charCodeAt(0));

            // Decrypt the keys
            const decryptedPublicKey = await window.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                encryptionKey,
                encryptedPublicKey
            );

            const decryptedPrivateKey = await window.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                encryptionKey,
                encryptedPrivateKey
            );

            // Convert decrypted keys to base64 strings
            const publicKeyStr = String.fromCharCode(...new Uint8Array(decryptedPublicKey));
            const privateKeyStr = String.fromCharCode(...new Uint8Array(decryptedPrivateKey));

            // Import the RSA keys
            this.publicKey = await window.crypto.subtle.importKey(
                'spki',
                Uint8Array.from(atob(publicKeyStr), c => c.charCodeAt(0)),
                { name: 'RSA-OAEP', hash: 'SHA-256' },
                true,
                ['encrypt']
            );

            this.privateKey = await window.crypto.subtle.importKey(
                'pkcs8',
                Uint8Array.from(atob(privateKeyStr), c => c.charCodeAt(0)),
                { name: 'RSA-OAEP', hash: 'SHA-256' },
                true,
                ['decrypt']
            );
            
            console.log('Keys imported successfully');
        } catch (error) {
            console.error('Error decrypting keys:', error);
            this.showError('Failed to initialize encryption. Please try again.');
            return;
        }
        
        this.render();
        if (chatId) {
            this.loadMessages();
        }
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

            // Encrypt the message content if we have a public key
            let encryptedContent = content;
            if (this.publicKey) {
                const encoder = new TextEncoder();
                const encodedContent = encoder.encode(content);
                encryptedContent = await window.crypto.subtle.encrypt(
                    { name: 'RSA-OAEP' },
                    this.publicKey,
                    encodedContent
                );
                encryptedContent = btoa(String.fromCharCode(...new Uint8Array(encryptedContent)));
            }

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
            this.messages.push(data.message);
            this.render();
            
            // Clear the input
            const textarea = this.container.querySelector('textarea');
            if (textarea) {
                textarea.value = '';
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