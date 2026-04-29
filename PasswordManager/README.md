# Password Manager

A professional-grade password manager using Python's Cryptography library with PBKDF2-SHA256 key derivation, SQLite database storage, and comprehensive security features.

## Features

### Security Features
- **PBKDF2-SHA256 Key Derivation**: Professional-grade master password security with 100,000 iterations
- **AES-128 Encryption**: Uses Fernet for authenticated encryption
- **Zero-Knowledge Architecture**: Master password derived, never stored directly
- **Environment Variables**: Configurable settings via .env file

### Core Functionality
- **Interactive CLI**: User-friendly command-line interface with 10 menu options
- **Secure Password Input**: Uses `getpass` to hide password entry
- **SQLite Database**: Robust storage with timestamps and metadata
- **Password Generation**: Configurable complexity with customizable options
- **Search & Filter**: Find passwords by site name with partial matching
- **Import/Export**: JSON format for backup and migration
- **Password Expiration**: Track and manage password lifecycle
- **Multi-field Support**: Username, notes, and custom expiry dates

### Database Schema
- **Passwords Table**: Site, username, encrypted password, timestamps, expiry, notes
- **Master Key Table**: Secure salt storage for PBKDF2
- **Automatic Cleanup**: Handles expired and invalid entries gracefully

## Installation

1. Install the required libraries:
```bash
pip install -r requirements.txt
```

2. Run the password manager:
```bash
python password_manager.py
```

3. First-time setup:
- Create a master password (minimum 8 characters)
- Remember it - it cannot be recovered!
- Configure optional settings via `.env` file

## Security Principles

### Zero-Knowledge Architecture
- **PBKDF2-SHA256**: 100,000 iterations for master password derivation
- **Salt Storage**: Unique salt per installation stored securely in database
- **No Key Storage**: Master password never stored, only derived on-the-fly
- **Memory Safety**: Keys cleared from memory when possible

### Key Storage Best Practices
- **NEVER** store the master password anywhere
- **Database Security**: SQLite file contains only encrypted data and salt
- **Backup Strategy**: Backup both database and remember master password separately
- **Physical Security**: Ensure your computer is physically secure

### Environment Configuration
Configure via `.env` file:
```bash
# Database file path
DB_PATH=passwords.db

# Password expiration settings (in days)
PASSWORD_EXPIRY_DAYS=90

# PBKDF2 settings
PBKDF2_ITERATIONS=100000
SALT_LENGTH=32

# Export/Import settings
EXPORT_FORMAT=json
BACKUP_ENABLED=true
```

## Usage

### First Run
1. The program prompts to create a master password
2. Enter and confirm your master password (min 8 characters)
3. Remember it - it cannot be recovered!

### Menu Options
1. **Add new password**: Store with optional username, notes, and custom expiry
2. **View all passwords**: Display all active passwords with metadata
3. **Search password**: Find specific passwords by partial site name
4. **Delete password**: Remove entries with confirmation
5. **Generate secure password**: Create strong passwords with configurable options
6. **Export passwords**: Backup to JSON file (unencrypted for migration)
7. **Import passwords**: Restore from JSON backup file
8. **Check expired passwords**: Quick summary of expired entries
9. **View expired passwords**: Show all expired passwords
10. **Exit**: Close the program

### Password Generation Options
- **Length**: Customizable (default 16 characters)
- **Character Sets**: Uppercase, lowercase, digits, symbols
- **Ambiguous Characters**: Option to exclude confusing characters (ilLI1oO0)
- **Cryptographically Secure**: Uses `secrets` module for randomness

## File Structure

```
CyberHack/
├── password_manager.py  # Main application
├── passwords.db         # SQLite database (encrypted passwords + salt)
├── .env                 # Configuration file (create from .env.example)
├── requirements.txt     # Dependencies
└── README.md            # This file
```

### Database Schema
```sql
-- Passwords table
CREATE TABLE passwords (
    id UUID PRIMARY KEY AUTOINCREMENT,
    site TEXT NOT NULL,
    username TEXT,
    encrypted_password TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    notes TEXT
);

-- Master key table (stores salt only)
CREATE TABLE master_key (
    id UUID PRIMARY KEY,
    salt BLOB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Security Warnings

- **Master Password**: Cannot be recovered if lost - store securely
- **Database Security**: Keep `passwords.db` file secure and backed up
- **Export Files**: JSON exports contain unencrypted passwords - handle securely
- **Physical Security**: Ensure your computer is physically secure
- **Memory Security**: Keys are cleared from memory when possible
- **Backup Strategy**: Regular backups of database + separate master password storage
- **Environment Variables**: Keep `.env` file secure and don't commit to version control

## Advanced Features

### Implemented Features
- **PBKDF2-SHA256 Key Derivation**: 100,000 iterations for master password security
- **SQLite Database Storage**: Robust, structured data storage with metadata
- **Password Generation**: Configurable complexity and length
- **Export/Import**: JSON format for backup and migration
- **Password Expiration**: Automatic tracking and management
- **Environment Variables**: Flexible configuration via .env file
- **Advanced Search**: Partial matching and filtering
- **Multi-field Support**: Username, notes, custom expiry dates

### Future Enhancements
- **Web Interface**: HTTPS web interface with authentication
- **Two-Factor Authentication**: TOTP integration
- **Password Strength Analysis**: Real-time strength checking
- **Database Encryption**: Additional layer of database encryption
- **Cloud Sync**: Encrypted cloud synchronization
- **Mobile App**: Cross-platform mobile application
- **API Integration**: REST API for third-party integrations
- **Audit Logging**: Comprehensive access and change logging

## License

This project is for educational purposes. Use at your own risk and consider professional password managers like Bitwarden for critical applications.

## Security Considerations

This password manager implements industry-standard security practices:
- **PBKDF2-SHA256**: Recommended key derivation function
- **AES-128**: Proven encryption standard
- **Authenticated Encryption**: Prevents tampering attacks
- **Secure Random Generation**: Uses cryptographically secure random number generators
- **Memory Safety**: Minimizes sensitive data exposure

However, for mission-critical applications, consider established solutions like:
- **Bitwarden**: Open-source, audited password manager
- **1Password**: Commercial solution with advanced features
- **KeePass**: Local-first open-source option

## Troubleshooting

### Common Issues
1. **Installation Problems**:
   - Ensure Python 3.7+ is installed
   - Install dependencies: `pip install -r requirements.txt`
   - Check that `cryptography` and `python-dotenv` are properly installed

2. **Database Issues**:
   - Ensure file permissions allow read/write access to `passwords.db`
   - Check that the database is not corrupted (run integrity check)
   - Verify SQLite is available on your system

3. **Master Password Issues**:
   - Master password cannot be recovered - keep it safe
   - Minimum 8 characters required
   - Case-sensitive authentication

4. **Import/Export Issues**:
   - JSON files must be properly formatted
   - Export files contain unencrypted passwords - handle securely
   - Ensure file permissions allow read/write operations

### Getting Help
- Check the error messages for specific guidance
- Verify all dependencies are installed correctly
- Ensure the `.env` file exists and is properly configured
- Test with a fresh database if corruption is suspected

---

**Remember**: The security of your passwords depends on the security of your master key file!
