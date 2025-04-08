-- Drop existing chat_keys table
DROP TABLE IF EXISTS chat_keys CASCADE;

-- Create new chat_keys table with Signal Protocol fields
CREATE TABLE chat_keys (
    id SERIAL PRIMARY KEY,
    chat_id INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    registration_id INTEGER,
    identity_public_key TEXT,
    signed_pre_public_key TEXT,
    signature TEXT,
    one_time_pre_keys TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(chat_id, user_id)
); 