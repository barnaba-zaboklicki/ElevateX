# Database Documentation

## Overview
This document provides a comprehensive guide to the Innovation Hub Platform database structure, including tables, relationships, security measures, and data management.

## Table of Contents
1. [Database Schema](#database-schema)
2. [User Management](#user-management)
3. [Core Features](#core-features)
4. [Security Implementation](#security-implementation)
5. [Performance Optimization](#performance-optimization)
6. [Data Management](#data-management)

## Database Schema

### 1. Users Table
```sql
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
```
**Purpose**: Stores user information and authentication details
**Key Features**:
- Unique email constraint
- Password hashing
- Role-based access control
- Activity tracking
- Timestamp management

### 2. Inventions Table
```sql
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
```
**Purpose**: Stores invention details and status
**Key Features**:
- Status tracking
- Category classification
- Patent and funding status
- Timestamp management
- Inventor relationship

### 3. Documents Table
```sql
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
```
**Purpose**: Manages invention-related documents
**Key Features**:
- S3 integration
- File type tracking
- Confidentiality flag
- Upload tracking
- Encryption key storage

### 4. Investments Table
```sql
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
```
**Purpose**: Tracks investment transactions
**Key Features**:
- Amount tracking
- Status management
- Terms storage
- Timestamp tracking
- Investor relationship

### 5. Research Table
```sql
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
```
**Purpose**: Stores research findings
**Key Features**:
- Research type categorization
- Findings storage
- Status tracking
- Timestamp management
- Researcher relationship

### 6. Notifications Table
```sql
CREATE TABLE notifications (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    type VARCHAR(50) NOT NULL,
    content TEXT NOT NULL,
    is_read BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```
**Purpose**: Handles system notifications
**Key Features**:
- Type categorization
- Read status tracking
- Timestamp management
- User relationship

## User Management

### Role Types
```sql
CREATE TYPE user_role AS ENUM ('admin', 'inventor', 'investor', 'researcher');
```
**Role Permissions**:

1. **Admin**
   - Full system access
   - User management
   - Content moderation
   - System configuration

2. **Inventor**
   - Create inventions
   - Manage own inventions
   - Upload documents
   - Receive investments
   - Communicate with investors through secure messaging

3. **Investor**
   - View inventions
   - Make investments
   - View investment terms
   - Track investments
   - Communicate with inventors through secure messaging

4. **Researcher**
   - View inventions
   - Add research findings
   - Track research progress

## Security Implementation

### 1. Password Security
- Passwords are hashed using bcrypt
- Never stored in plain text
- Salted for additional security

### 2. Data Encryption
**AES Encryption for**:
- Invention descriptions
- Technical details
- Investment terms
- Research findings
- Notification content

### 3. Transport Security
- SSL/TLS for database connections
- HTTPS for API endpoints
- Encrypted S3 uploads

### 4. Secure Communication
- Dedicated encrypted messaging service for investor-inventor communication
- End-to-end encryption for all messages
- Secure message storage and retrieval
- Message access control based on user roles

## Performance Optimization

### Indexes
```sql
-- User Indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);

-- Invention Indexes
CREATE INDEX idx_inventions_inventor ON inventions(inventor_id);
CREATE INDEX idx_inventions_status ON inventions(status);
CREATE INDEX idx_inventions_category ON inventions(category);

-- Document Indexes
CREATE INDEX idx_documents_invention ON documents(invention_id);
CREATE INDEX idx_documents_uploaded_by ON documents(uploaded_by);

-- Investment Indexes
CREATE INDEX idx_investments_invention ON investments(invention_id);
CREATE INDEX idx_investments_investor ON investments(investor_id);
CREATE INDEX idx_investments_status ON investments(status);

-- Research Indexes
CREATE INDEX idx_research_invention ON research(invention_id);
CREATE INDEX idx_research_researcher ON research(researcher_id);

-- Notification Indexes
CREATE INDEX idx_notifications_user ON notifications(user_id);
CREATE INDEX idx_notifications_read ON notifications(is_read);
```

## Data Management

### Timestamp Management
```sql
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';
```
**Automatic Updates for**:
- Users
- Inventions
- Investments
- Research

### Data Integrity
- Foreign key constraints
- Enum type restrictions
- NOT NULL constraints
- Unique constraints
- Default values

## Best Practices

1. **Data Access**
   - Use prepared statements
   - Implement connection pooling
   - Follow principle of least privilege

2. **Performance**
   - Use appropriate indexes
   - Implement caching where needed
   - Optimize query patterns

3. **Security**
   - Regular security audits
   - Backup procedures
   - Access logging
   - Encryption key rotation

4. **Maintenance**
   - Regular vacuum operations
   - Index maintenance
   - Performance monitoring
   - Backup verification 