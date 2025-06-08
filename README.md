# Secure User Data Management System

A PHP-based web application that demonstrates secure handling of sensitive user data using multiple encryption methods. The system implements secure user registration, login, and data display functionality with encrypted data storage.

## Features

- User Registration with encrypted data storage
- Secure Login System
- Encrypted storage of sensitive information:
  - Name
  - Phone Number
  - Address
  - Social Security Number
  - Email
- Session-based authentication
- Secure data display in dashboard

## Security Implementation

### Encryption Methods
- **Symmetric Encryption**:
  - **AES-256-GCM** (Advanced Encryption Standard)
    - **Key Length**: 256-bit
    - **Mode**: Galois/Counter Mode
    - **IV Handling**: Unique IV for each encrypted field
    - **Data Format**: Base64 encoded (IV + encrypted data)
  - **ChaCha20**
    - **Key Length**: 256-bit
    - **Mode**: Stream Cipher
    - **IV Handling**: Unique IV for each encrypted field
    - **Data Format**: Base64 encoded (IV + encrypted data)

- **Asymmetric Encryption**:
  - **RSA** (Rivest-Shamir-Adleman)
    - **Key Length**: 2048-bit
    - **Implementation**: OpenSSL
    - **Data Format**: Base64 encoded (encrypted data)
  - **NTRU** (Post-Quantum Cryptography)
    - **Implementation**: Custom NTRU implementation
    - **Security Level**: Post-quantum resistant
  - **Paillier** (Homomorphic Encryption)
    - **Implementation**: Custom Paillier implementation
    - **Feature**: Supports homomorphic operations

### Key Management
- **Key Storage**: Secure key management using dedicated `keys/` directory
- **Key Generation**: Automatic key pair generation for asymmetric encryption
- **Environment Variables**: Use environment variables for key storage in production

### Password Security
- Passwords are hashed using PHP's `password_hash()` with BCRYPT
- Secure password verification using `password_verify()`

### Data Protection
- All sensitive user data is encrypted before storage
- Unique IV for each piece of data
- Data is only decrypted when needed for display
- Session-based authentication required to view data

## Technical Requirements

- PHP 7.0 or higher
- MySQL/MariaDB
- OpenSSL PHP extension
- Apache/Nginx web server
- XAMPP (recommended for local development)

## Project Structure

```
├── config/
│   ├── database.php
│   └── user_data.sql
├── security/
│   ├── asymmetric/
│   │   ├── ecc_encryption.php
│   │   ├── ntru_encryption.php
│   │   └── paillier_encryption.php
│   ├── symmetric/
│   |   ├── aes_gcm.php
│   |   └── chacha20.php
|   ├── homomorphic
|   |   ├── homomorphic_key_management.php
|   |   └── pailler_encryption.php
|   └── key_management.php
├── keys/
│   └── (encryption keys storage)
├── view/
|   ├── app/
|   |     ├── style.css
│   ├── dashboard.php
│   ├── login.php
│   ├── logout.php
│   └── register.php
└── README.md

## Setup Instructions

1. Clone the repository to your web server directory
2. Import the database structure using `config/user_data.sql`
3. Configure database connection in `config/database.php`
4. Ensure proper file permissions are set for the `keys/` directory
5. Access the application through your web browser

## Security Notes

For Production Environment:
1. Store encryption keys securely (not in source code)
2. Use environment variables for sensitive configuration
3. Implement proper session management
4. Enable HTTPS
5. Implement rate limiting
6. Add input validation and sanitization
7. Implement CSRF protection
8. Regular security audits and updates

## Development Mode Warning

The current implementation includes a hardcoded encryption key for development purposes. In a production environment, this should be replaced with secure key management.

## License

This project is intended for educational purposes. Use in production environments requires additional security measures.

## Contributing

Feel free to submit issues and enhancement requests.

## Disclaimer

This is a demonstration project and should not be used as-is in a production environment without proper security review and enhancements.
