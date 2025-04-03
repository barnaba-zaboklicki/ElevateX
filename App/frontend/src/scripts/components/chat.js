class Chat {
    constructor(containerId) {
        this.containerId = containerId;
        this.container = document.getElementById(containerId);
        this.inventorName = '';
        this.inventionTitle = '';
        this.chatId = '';
        this.messages = [];
    }

    initialize(inventorName, inventionTitle, chatId) {
        this.inventorName = inventorName;
        this.inventionTitle = inventionTitle;
        this.chatId = chatId;
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

            const response = await fetch(`https://127.0.0.1:5000/api/messages/${this.chatId}/send`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({ content }),
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