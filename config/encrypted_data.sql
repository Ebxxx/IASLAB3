-- Create table for storing encrypted personal data
CREATE TABLE personal_data (
    id INT PRIMARY KEY AUTO_INCREMENT,
    -- Encrypted data fields
    encrypted_name TEXT NOT NULL,
    encrypted_age TEXT NOT NULL,
    encrypted_phone_number TEXT NOT NULL,
    encrypted_address TEXT NOT NULL,
    
    -- Encryption metadata
    encryption_method ENUM('AES-GCM', 'CHACHA20') NOT NULL,
    iv_nonce VARCHAR(24) NOT NULL,  -- Base64 encoded IV (for AES-GCM) or nonce (for ChaCha20)
    auth_tag VARCHAR(24),           -- Base64 encoded authentication tag (for AES-GCM only)
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Add indexes for better query performance
CREATE INDEX idx_encryption_method ON personal_data(encryption_method);
CREATE INDEX idx_created_at ON personal_data(created_at);
