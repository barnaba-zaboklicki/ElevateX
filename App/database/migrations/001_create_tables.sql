-- Transaction 1: Drop everything
BEGIN;

DROP TYPE IF EXISTS user_role CASCADE;
DROP TYPE IF EXISTS invention_status CASCADE;
DROP TYPE IF EXISTS investment_status CASCADE;

DROP TABLE IF EXISTS notifications CASCADE;
DROP TABLE IF EXISTS research CASCADE;
DROP TABLE IF EXISTS investments CASCADE;
DROP TABLE IF EXISTS documents CASCADE;
DROP TABLE IF EXISTS inventions CASCADE;
DROP TABLE IF EXISTS users CASCADE;

COMMIT;

-- Transaction 2: Create types
BEGIN;

CREATE TYPE user_role AS ENUM ('admin', 'inventor', 'investor', 'researcher');
CREATE TYPE invention_status AS ENUM ('draft', 'pending', 'approved', 'rejected');
CREATE TYPE investment_status AS ENUM ('pending', 'approved', 'rejected');

COMMIT;

-- Transaction 3: Create users table
BEGIN;

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    role user_role NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMIT;

-- Transaction 4: Create inventions table
BEGIN;

CREATE TABLE inventions (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    status invention_status DEFAULT 'draft',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    inventor_id INTEGER REFERENCES users(id),
    category VARCHAR(100),
    technical_details TEXT,
    patent_status VARCHAR(100),
    funding_status VARCHAR(100)
);

COMMIT;

-- Transaction 5: Create documents table
BEGIN;

CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    invention_id INTEGER REFERENCES inventions(id),
    title VARCHAR(255) NOT NULL,
    file_path VARCHAR(255) NOT NULL,
    file_type VARCHAR(50),
    encryption_key VARCHAR(255),
    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    uploaded_by INTEGER REFERENCES users(id),
    is_confidential BOOLEAN DEFAULT false
);

COMMIT;

-- Transaction 6: Create investments table
BEGIN;

CREATE TABLE investments (
    id SERIAL PRIMARY KEY,
    invention_id INTEGER REFERENCES inventions(id),
    investor_id INTEGER REFERENCES users(id),
    amount DECIMAL(10,2) NOT NULL,
    status investment_status DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    terms TEXT
);

COMMIT;

-- Transaction 7: Create research table
BEGIN;

CREATE TABLE research (
    id SERIAL PRIMARY KEY,
    invention_id INTEGER REFERENCES inventions(id),
    researcher_id INTEGER REFERENCES users(id),
    research_type VARCHAR(100),
    findings TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50)
);

COMMIT;

-- Transaction 8: Create notifications table
BEGIN;

CREATE TABLE notifications (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    type VARCHAR(50) NOT NULL,
    content TEXT NOT NULL,
    is_read BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMIT;

-- Transaction 9: Create indexes
BEGIN;

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_inventions_inventor ON inventions(inventor_id);
CREATE INDEX idx_inventions_status ON inventions(status);
CREATE INDEX idx_inventions_category ON inventions(category);
CREATE INDEX idx_documents_invention ON documents(invention_id);
CREATE INDEX idx_documents_uploaded_by ON documents(uploaded_by);
CREATE INDEX idx_investments_invention ON investments(invention_id);
CREATE INDEX idx_investments_investor ON investments(investor_id);
CREATE INDEX idx_investments_status ON investments(status);
CREATE INDEX idx_research_invention ON research(invention_id);
CREATE INDEX idx_research_researcher ON research(researcher_id);
CREATE INDEX idx_notifications_user ON notifications(user_id);
CREATE INDEX idx_notifications_read ON notifications(is_read);

COMMIT;

-- Transaction 10: Create trigger function and triggers
BEGIN;

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_inventions_updated_at
    BEFORE UPDATE ON inventions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_investments_updated_at
    BEFORE UPDATE ON investments
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_research_updated_at
    BEFORE UPDATE ON research
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

COMMIT; 