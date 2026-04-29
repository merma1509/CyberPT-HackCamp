import os
import sys
import getpass
import json
from datetime import datetime, timedelta

# Import modular components
from config import settings
from database import db_manager
from cryptographer import crypto_manager
from generator import password_generator

class PasswordManager:
    """Main password manager class using modular components"""
    
    def __init__(self):
        # Configuration is handled by config module
        self.config = settings
        
        # Database and crypto managers are initialized globally
        self.db = db_manager
        self.crypto = crypto_manager
        self.generator = password_generator

    
    def create_master_password(self):
        """Create a master password with PBKDF2 key derivation."""
        while True:
            password = getpass.getpass("Enter new master password: ")
            confirm_password = getpass.getpass("Confirm master password: ")
            
            if password != confirm_password:
                print("Passwords do not match. Try again.")
                continue
                
            if self.crypto.create_master_password(password):
                print("Master password created successfully!")
                print("  Remember your master password - it cannot be recovered!")
                break


    def load_master_password(self):
        """Load and verify master password."""
        if not self.db.master_password_exists():
            print("No master password found. Please create one first.")
            return False
            
        password = getpass.getpass("Enter master password: ")
        return self.crypto.load_master_password(password)

    def generate_password(self, length=None, use_uppercase=True, use_lowercase=True, 
                         use_digits=True, use_symbols=True, exclude_ambiguous=True):
        """Generate a secure random password with configurable complexity."""
        return self.generator.generate_password(
            length=length,
            use_uppercase=use_uppercase,
            use_lowercase=use_lowercase,
            use_digits=use_digits,
            use_symbols=use_symbols,
            exclude_ambiguous=exclude_ambiguous
        )

    def add_password(self, site, username=None, password=None, notes=None, expiry_days=None):
        """Encrypts and stores a password in the database."""
        if not password:
            # Ask if user wants to generate a password
            generate = input("Generate secure password? (y/n): ").lower() == 'y'
            if generate:
                try:
                    length = int(input("Password length (default 16): ") or "16")
                    password = self.generate_password(length=length)
                    print(f"🔑 Generated password: {password}")
                except ValueError as e:
                    print(f"Error generating password: {e}")
                    return
            else:
                password = getpass.getpass(f"Enter password for {site}: ")
        
        if not username:
            username = input(f"Enter username for {site} (optional): ") or None
            
        if not notes:
            notes = input(f"Enter notes for {site} (optional): ") or None
        
        # Calculate expiry date
        expiry_days = expiry_days or self.config.get_password_expiry_days()
        expires_at = datetime.now() + timedelta(days=expiry_days)
        
        # Encrypt password
        encrypted_password = self.crypto.encrypt_password(password)
        
        # Store in database
        password_id = self.db.add_password(site, username, encrypted_password, expires_at, notes)
        
        print(f"Password for {site} added successfully!")
        print(f"Expires on: {expires_at.strftime('%Y-%m-%d')}")

    def view_passwords(self, show_expired=False):
        """Decrypts and displays stored passwords from database."""
        results = self.db.get_all_passwords(include_expired=show_expired)
        
        if not results:
            print("No passwords stored." if not show_expired else "No expired passwords found.")
            return
            
        print(f"\n{'Stored' if not show_expired else 'Expired'} Passwords:")
        print("=" * 80)
        
        for row in results:
            try:
                pid, site, username, encrypted_pw, created_at, expires_at, notes = row
                decrypted_pw = self.crypto.decrypt_password(encrypted_pw)
                
                # Check if expired
                is_expired = expires_at and datetime.fromisoformat(expires_at) < datetime.now()
                
                print(f"Site: {site}")
                if username:
                    print(f"Username: {username}")
                print(f"Password: {decrypted_pw}")
                print(f"Created: {created_at}")
                if expires_at:
                    status = "EXPIRED" if is_expired else "Valid"
                    print(f"Expires: {expires_at} {status}")
                if notes:
                    print(f"Notes: {notes}")
                print("-" * 80)
            except Exception as e:
                print(f"Error decrypting entry {pid}: {e}")

    def search_password(self, site):
        """Search for passwords by site name."""
        results = self.db.search_passwords(site)
        
        if not results:
            print(f"No passwords found for '{site}'")
            return
            
        print(f"\nSearch Results for '{site}':")
        print("=" * 80)
        
        for row in results:
            try:
                pid, site_name, username, encrypted_pw, created_at, expires_at, notes = row
                decrypted_pw = self.crypto.decrypt_password(encrypted_pw)
                
                print(f"Site: {site_name}")
                if username:
                    print(f"Username: {username}")
                print(f"Password: {decrypted_pw}")
                print(f"Created: {created_at}")
                if expires_at:
                    is_expired = datetime.fromisoformat(expires_at) < datetime.now()
                    status = "EXPIRED" if is_expired else "Valid"
                    print(f"Expires: {expires_at} {status}")
                if notes:
                    print(f"Notes: {notes}")
                print("-" * 80)
            except Exception as e:
                print(f"Error decrypting entry {pid}: {e}")

    def delete_password(self, site):
        """Delete password entries by site name."""
        # Show what will be deleted
        results = self.db.search_passwords(site)
        
        if not results:
            print(f"No passwords found for '{site}'")
            return
            
        print(f"Found {len(results)} password(s) to delete:")
        for pid, site_name, _, _, _, _, _ in results:
            print(f"  - {site_name} (ID: {pid})")
            
        confirm = input("Delete these passwords? (y/n): ").lower() == 'y'
        if confirm:
            deleted_count = self.db.delete_passwords(site)
            print(f"Deleted {deleted_count} password(s)")
        else:
            print("Deletion cancelled")

    def export_passwords(self, filename=None):
        """Export passwords to JSON file."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"password_export_{timestamp}.json"
            
        results = self.db.get_passwords_for_export()
        
        export_data = []
        for row in results:
            try:
                site, username, encrypted_pw, created_at, expires_at, notes = row
                decrypted_pw = self.crypto.decrypt_password(encrypted_pw)
                
                entry = {
                    "site": site,
                    "username": username,
                    "password": decrypted_pw,
                    "created_at": created_at,
                    "expires_at": expires_at,
                    "notes": notes
                }
                export_data.append(entry)
            except Exception as e:
                print(f"Skipping entry due to decryption error: {e}")
                
        with open(filename, 'w') as f_out:
            json.dump(export_data, f_out, indent=2)
            
        print(f"Exported {len(export_data)} passwords to {filename}")
        print("Keep this file secure - it contains unencrypted passwords!")

    def import_passwords(self, filename):
        """Import passwords from JSON file."""
        if not os.path.exists(filename):
            print(f"File {filename} not found")
            return
            
        try:
            with open(filename, 'r') as f_in:
                import_data = json.load(f_in)
                
            if not isinstance(import_data, list):
                print("Invalid import file format")
                return
                
            # Process import data
            passwords_data = []
            for entry in import_data:
                try:
                    site = entry.get('site')
                    username = entry.get('username')
                    password = entry.get('password')
                    notes = entry.get('notes')
                    
                    if not site or not password:
                        print(f"Skipping entry with missing site or password")
                        continue
                        
                    # Encrypt password
                    encrypted_password = self.crypto.encrypt_password(password)
                    
                    passwords_data.append({
                        'site': site,
                        'username': username,
                        'encrypted_password': encrypted_password,
                        'notes': notes
                    })
                except Exception as e:
                    print(f"Error processing entry for {site}: {e}")
                    
            # Import to database
            imported_count = self.db.import_passwords(passwords_data)
            print(f"Successfully imported {imported_count} passwords")
            
        except json.JSONDecodeError:
            print("Invalid JSON file format")
        except Exception as e:
            print(f"Error importing passwords: {e}")

    def check_expired_passwords(self):
        """Check and display expired passwords."""
        expired = self.db.get_expired_passwords()
        
        if expired:
            print(f"\nFound {len(expired)} expired password(s):")
            for site, username, expires_at in expired:
                print(f"  - {site} ({'@' + username if username else 'no username'}) - Expired: {expires_at}")
        else:
            print("No expired passwords found")

    def show_menu(self):
        """Display the interactive menu."""
        title = "Password Manager 2026 - Advanced Edition"
        if self.config.should_show_emojis():
            title = f"{title}"
        
        print(f"\n{title}")
        print("=" * 50)
        print("1. Add new password")
        print("2. View all passwords")
        print("3. Search password")
        print("4. Delete password")
        print("5. Generate secure password")
        print("6. Export passwords")
        print("7. Import passwords")
        print("8. Check expired passwords")
        print("9. View expired passwords")
        print("10. Exit")
        print("=" * 50)

def main():
    """Main interactive program."""
    pm = PasswordManager()
    
    # Check if master password exists
    if not pm.db.master_password_exists():
        print("No master password found. Creating a new one...")
        pm.create_master_password()
    
    if not pm.load_master_password():
        return
    
    while True:
        pm.show_menu()
        try:
            choice = input("\nEnter your choice (1-10): ").strip()
            
            if choice == "1":
                site = input("Enter site name: ").strip()
                if site:
                    pm.add_password(site)
                else:
                    print("Site name cannot be empty!")
            
            elif choice == "2":
                pm.view_passwords()
            
            elif choice == "3":
                site = input("Enter site name to search: ").strip()
                if site:
                    pm.search_password(site)
                else:
                    print("Search term cannot be empty!")
            
            elif choice == "4":
                site = input("Enter site name to delete: ").strip()
                if site:
                    pm.delete_password(site)
                else:
                    print("Site name cannot be empty!")
            
            elif choice == "5":
                try:
                    length = int(input("Password length (default 16): ") or "16")
                    password = pm.generate_password(length=length)
                    print(f"Generated password: {password}")
                except ValueError as e:
                    print(f"Error: {e}")
            
            elif choice == "6":
                filename = input("Export filename (optional): ").strip() or None
                pm.export_passwords(filename)
            
            elif choice == "7":
                filename = input("Import filename: ").strip()
                if filename:
                    pm.import_passwords(filename)
                else:
                    print("Filename cannot be empty!")
            
            elif choice == "8":
                pm.check_expired_passwords()
            
            elif choice == "9":
                pm.view_passwords(show_expired=True)
            
            elif choice == "10":
                print("Goodbye!")
                break
            
            else:
                print("Invalid choice! Please enter 1-10.")
                
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
