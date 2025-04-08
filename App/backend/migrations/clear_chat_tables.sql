-- Clear all chat-related tables
DELETE FROM messages CASCADE;
DELETE FROM chat_keys CASCADE;
DELETE FROM chat_participants CASCADE;
DELETE FROM chats CASCADE;

-- Reset sequences
ALTER SEQUENCE IF EXISTS messages_id_seq RESTART WITH 1;
ALTER SEQUENCE IF EXISTS chat_keys_id_seq RESTART WITH 1;
ALTER SEQUENCE IF EXISTS chat_participants_id_seq RESTART WITH 1;
ALTER SEQUENCE IF EXISTS chats_id_seq RESTART WITH 1; 