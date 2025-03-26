# Database Entity Relationship Diagram

## Entities

### Users
- id (PK)
- email (unique)
- password_hash (encrypted)
- first_name
- last_name
- role (enum: admin, inventor, investor, researcher)
- is_active
- created_at
- last_login
- updated_at

### Inventions
- id (PK)
- title
- description (encrypted)
- status (enum: draft, pending, approved, rejected)
- created_at
- updated_at
- inventor_id (FK -> Users)
- category
- technical_details (encrypted)
- patent_status
- funding_status

### Documents
- id (PK)
- invention_id (FK -> Inventions)
- title
- file_path (S3)
- file_type
- encryption_key (encrypted)
- uploaded_at
- uploaded_by (FK -> Users)
- is_confidential

### Investments
- id (PK)
- invention_id (FK -> Inventions)
- investor_id (FK -> Users)
- amount
- status (enum: pending, approved, rejected)
- created_at
- updated_at
- terms (encrypted)

### Research
- id (PK)
- invention_id (FK -> Inventions)
- researcher_id (FK -> Users)
- research_type
- findings (encrypted)
- created_at
- updated_at
- status

### Notifications
- id (PK)
- user_id (FK -> Users)
- type
- content (encrypted)
- is_read
- created_at

## Relationships

1. Users -> Inventions (1:N)
   - One user can have many inventions
   - Each invention belongs to one user (inventor)

2. Inventions -> Documents (1:N)
   - One invention can have many documents
   - Each document belongs to one invention

3. Inventions -> Investments (1:N)
   - One invention can have many investments
   - Each investment is for one invention

4. Users -> Investments (1:N)
   - One user (investor) can have many investments
   - Each investment belongs to one user

5. Inventions -> Research (1:N)
   - One invention can have many research entries
   - Each research entry is for one invention

6. Users -> Research (1:N)
   - One user (researcher) can have many research entries
   - Each research entry belongs to one user

7. Users -> Notifications (1:N)
   - One user can have many notifications
   - Each notification belongs to one user

8. Users -> Secure Messages (1:N)
   - One user can have many messages
   - Each message belongs to one user
   - Messages are managed by a separate encrypted messaging service

## Encryption Points

1. **Application Level Encryption (AES)**
   - User passwords (hashed with bcrypt)
   - Invention descriptions
   - Technical details
   - Investment terms
   - Research findings
   - Notification content

2. **Transport Level Encryption (TLS/SSL)**
   - All database connections
   - API endpoints
   - File uploads to S3

3. **Secure Messaging**
   - End-to-end encryption for all messages
   - Secure message storage
   - Message access control

## Indexes

1. Users
   - email (unique)
   - role

2. Inventions
   - inventor_id
   - status
   - category

3. Documents
   - invention_id
   - uploaded_by

4. Investments
   - invention_id
   - investor_id
   - status

5. Research
   - invention_id
   - researcher_id

6. Notifications
   - user_id
   - is_read 