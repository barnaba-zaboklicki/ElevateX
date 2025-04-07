let currentChat = null;

async function handleMenuClick(menuItem) {
    // ... existing code ...

    if (menuItem === 'messages') {
        // Clean up previous chat if it exists
        if (currentChat) {
            currentChat.cleanup();
        }

        // Initialize new chat
        currentChat = new Chat('main-content');
        await currentChat.initialize(chatData.invention_id, chatData.inventor_name, chatId);
    } else {
        // Clean up chat when switching to other views
        if (currentChat) {
            currentChat.cleanup();
            currentChat = null;
        }
        // ... rest of your menu handling code ...
    }
}

// Add cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (currentChat) {
        currentChat.cleanup();
    }
}); 