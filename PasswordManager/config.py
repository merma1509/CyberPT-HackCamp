"""Configuration management settings for Password Manager
   Handles environment variables and default settings"""

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("Warning: python-dotenv not installed. Using default configuration.")

class Settings:
    """Configuration class for password manager settings"""
    
    def __init__(self):
        # Database settings
        self.db_path = os.getenv('DB_PATH', 'passwords.db')
        self.db_path = str(Path(self.db_path).resolve())
        
        # Password expiration settings
        self.password_expiry_days = int(os.getenv('PASSWORD_EXPIRY_DAYS', '90'))
        
        # PBKDF2 settings
        self.pbkdf2_iterations = int(os.getenv('PBKDF2_ITERATIONS', '100000'))
        self.salt_length = int(os.getenv('SALT_LENGTH', '32'))
        
        # Export/Import settings
        self.export_format = os.getenv('EXPORT_FORMAT', 'json')
        self.backup_enabled = os.getenv('BACKUP_ENABLED', 'true').lower() == 'true'
        
        # Security settings
        self.min_master_password_length = int(os.getenv('MIN_MASTER_PASSWORD_LENGTH', '8'))
        self.default_password_length = int(os.getenv('DEFAULT_PASSWORD_LENGTH', '16'))
        
        # UI settings
        self.show_emojis = os.getenv('SHOW_EMOJIS', 'true').lower() == 'true'
        
    def get_db_path(self):
        """Get the database path"""
        return self.db_path
    
    def get_password_expiry_days(self):
        """Get password expiry days"""
        return self.password_expiry_days
    
    def get_pbkdf2_iterations(self):
        """Get PBKDF2 iterations count"""
        return self.pbkdf2_iterations
    
    def get_salt_length(self):
        """Get salt length for key derivation"""
        return self.salt_length
    
    def get_export_format(self):
        """Get export format"""
        return self.export_format
    
    def is_backup_enabled(self):
        """Check if backup is enabled"""
        return self.backup_enabled
    
    def get_min_master_password_length(self):
        """Get minimum master password length"""
        return self.min_master_password_length
    
    def get_default_password_length(self):
        """Get default password generation length"""
        return self.default_password_length
    
    def should_show_emojis(self):
        """Check if emojis should be displayed in UI"""
        return self.show_emojis

# Global configuration instance
settings = Settings()
