"""Database operations for Password Manager
   Handles SQLite database creation, queries, and data management"""

import sqlite3
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from config import settings

class DatabaseManager:
    """Manages SQLite database operations for password storage"""
    
    def __init__(self):
        self.db_path = settings.get_db_path()
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create passwords table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site TEXT NOT NULL,
                username TEXT,
                encrypted_password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                notes TEXT
            )
        ''')
        
        # Create master key table (stores salt only)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS master_key (
                id INTEGER PRIMARY KEY,
                salt BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def store_salt(self, salt: bytes) -> None:
        """Store salt in master_key table"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM master_key")  # Remove any existing salt
        cursor.execute("INSERT INTO master_key (salt) VALUES (?)", (salt,))
        conn.commit()
        conn.close()
    
    def get_salt(self) -> Optional[bytes]:
        """Retrieve salt from master_key table"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT salt FROM master_key LIMIT 1")
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None
    
    def master_password_exists(self) -> bool:
        """Check if master password (salt) exists"""
        return self.get_salt() is not None
    
    def add_password(self, site: str, username: Optional[str], 
                    encrypted_password: str, expires_at: datetime, 
                    notes: Optional[str]) -> int:
        """Add a new password entry"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO passwords (site, username, encrypted_password, expires_at, notes)
            VALUES (?, ?, ?, ?, ?)
        ''', (site, username, encrypted_password, expires_at, notes))
        password_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return password_id
    
    def get_all_passwords(self, include_expired: bool = True) -> List[Tuple]:
        """Retrieve all passwords"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = "SELECT id, site, username, encrypted_password, created_at, expires_at, notes FROM passwords"
        if not include_expired:
            query += " WHERE expires_at > datetime('now') OR expires_at IS NULL"
        
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        return results
    
    def search_passwords(self, search_term: str) -> List[Tuple]:
        """Search passwords by site name"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, site, username, encrypted_password, created_at, expires_at, notes
            FROM passwords WHERE LOWER(site) LIKE LOWER(?)
        ''', (f"%{search_term}%",))
        results = cursor.fetchall()
        conn.close()
        return results
    
    def delete_passwords(self, search_term: str) -> int:
        """Delete passwords matching search term"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # First, show what will be deleted
        cursor.execute('''
            SELECT id, site FROM passwords WHERE LOWER(site) LIKE LOWER(?)
        ''', (f"%{search_term}%",))
        results = cursor.fetchall()
        
        if not results:
            conn.close()
            return 0
        
        # Delete the passwords
        cursor.execute('''
            DELETE FROM passwords WHERE LOWER(site) LIKE LOWER(?)
        ''', (f"%{search_term}%",))
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        
        return deleted_count
    
    def get_expired_passwords(self) -> List[Tuple]:
        """Get all expired passwords"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT site, username, expires_at FROM passwords 
            WHERE expires_at < datetime('now')
        ''')
        expired = cursor.fetchall()
        conn.close()
        return expired
    
    def get_passwords_for_export(self) -> List[Tuple]:
        """Get all passwords for export (includes encrypted data)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT site, username, encrypted_password, created_at, expires_at, notes
            FROM passwords
        ''')
        results = cursor.fetchall()
        conn.close()
        return results
    
    def import_passwords(self, passwords_data: List[Dict]) -> int:
        """Import passwords from data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        imported_count = 0
        for entry in passwords_data:
            try:
                site = entry.get('site')
                username = entry.get('username')
                encrypted_password = entry.get('encrypted_password')
                notes = entry.get('notes')
                
                if not site or not encrypted_password:
                    continue
                
                # Calculate expiry date
                expiry_days = config.get_password_expiry_days()
                expires_at = datetime.now() + timedelta(days=expiry_days)
                
                # Store in database
                cursor.execute('''
                    INSERT INTO passwords (site, username, encrypted_password, expires_at, notes)
                    VALUES (?, ?, ?, ?, ?)
                ''', (site, username, encrypted_password, expires_at, notes))
                
                imported_count += 1
            except Exception:
                continue
        
        conn.commit()
        conn.close()
        return imported_count

# Global database manager instance
db_manager = DatabaseManager()
