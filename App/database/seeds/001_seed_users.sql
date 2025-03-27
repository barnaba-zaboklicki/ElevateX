-- Seed users table with sample data
BEGIN;

-- Admin user with hashed password 'admin123'
INSERT INTO users (
    email,
    password_hash,
    first_name,
    last_name,
    role,
    date_of_birth,
    is_active,
    created_at
) VALUES
    -- Admin user
    (
        'admin@elevatex.com',
        '$2b$10$9dirw3PudV4y4VYhV6ujfuFo5t8ufLVDreePRki.T3ieANnyc4pOi', -- 'admin123'
        'Barnaba',
        'Zaboklicki',
        'admin',
        '1993-12-16',
        true,
        CURRENT_TIMESTAMP
    );

COMMIT; 