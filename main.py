import bcrypt
import secrets
import string
import time
import sqlite3
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64

# To-do
# Encrypt the entire database using SQLCipher
# Unit testing
# Web UI with Flask

class PasswordManager:
    def __init__(self):
        self.master_hash = None
        self.master_salt = None
        self.is_authenticated = False
        self.fernet = None  
        self.DB_PATH = os.path.join(os.path.dirname(__file__), "password.db")
        self._initialize_database() 

    def _initialize_database(self):
        """Initialize database with all required tables"""
        try:
            with sqlite3.connect(self.DB_PATH) as connection:
                cursor = connection.cursor()

                # Add encryption_salt column 
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS secrets (
                        id INTEGER PRIMARY KEY,
                        encryption_salt TEXT NOT NULL
                    )
                ''')                

                # Initialize salt if empty
                cursor.execute("SELECT encryption_salt FROM secrets WHERE id = 1")
                if not cursor.fetchone():
                    new_salt = os.urandom(16)  
                    cursor.execute(
                        "INSERT INTO secrets (id, encryption_salt) VALUES (1, ?)",
                        (base64.b64encode(new_salt).decode(),)
                    )

                # Create master_password table
                master_password_table = '''CREATE TABLE IF NOT EXISTS master_password (
                    id INTEGER PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )'''
                cursor.execute(master_password_table)

                # Create passwords table
                password_table = '''CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY,
                    website TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )'''
                cursor.execute(password_table)

                connection.commit()
                
        except sqlite3.Error as e:
            print(f"Database initialization error: {e}")

    def _check_master_password_exists(self):
        """Check if a master password already exists in the database"""
        try:
            with sqlite3.connect(self.DB_PATH) as connection:
                cursor = connection.cursor()

                # Check if master password exists
                cursor.execute("SELECT password_hash, salt FROM master_password WHERE id = 1")
                result = cursor.fetchone()

                if result:
                    self.master_hash = result[0].encode('utf-8')
                    self.master_salt = result[1].encode('utf-8')
                    return True
                else:
                    return False
                
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return False
        
    def _generate_password(self, length=16):
        """Generate a random password"""
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(chars) for _ in range(length))
    
    def _check_complexity(self, password):
        """Check if password meets complexity requirements"""
        valid = True
        requirements = []
        
        if len(password) < 12:
            requirements.append("at least 12 characters")
            valid = False
        
        if not any(c.isupper() for c in password):
            requirements.append("uppercase letters")
            valid = False
        
        if not any(c.islower() for c in password):
            requirements.append("lowercase letters")
            valid = False
        
        if not any(c.isdigit() for c in password):
            requirements.append("digits")
            valid = False
        
        if not any(c in string.punctuation for c in password):
            requirements.append("symbols")
            valid = False
        
        if not valid:
            print(f"Password must contain: {', '.join(requirements)}")
        
        return valid
    
    def _get_user_password(self):
        """Get a user-created password that meets complexity requirements"""
        prompt = "Create password: " if self._check_master_password_exists() else "Create master password: "
        
        while True:
            password = input(prompt).strip()
            if self._check_complexity(password):
                print("Password created successfully.")
                return password

    def _hash_master_password(self, password):
        """Hash master password with bcrypt"""
        salt = bcrypt.gensalt()

        try:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
            
            with sqlite3.connect(self.DB_PATH) as connection:
                cursor = connection.cursor()
                
                # Store the hashed password in database 
                cursor.execute('''INSERT OR REPLACE INTO master_password 
                                (id, password_hash, salt) 
                                VALUES (1, ?, ?)''', 
                            (hashed_password.decode('utf-8'), salt.decode('utf-8')))
                
                connection.commit()       
                     
            return hashed_password, salt

        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return None, None
        
        except UnicodeEncodeError:
            print("Encoding error. Please try again with valid characters.")
            return None, None

    def _verify_master_password(self, attempt):
        """Verify an attempted master password"""
        try:
            hashed_attempt = bcrypt.hashpw(attempt.encode('utf-8'), self.master_salt)
            return secrets.compare_digest(hashed_attempt, self.master_hash)
        
        except UnicodeEncodeError:
            print("Encoding error. Please try again with valid characters.")
            return False

    def _derive_key(self, password):
        """Derive encryption key using the dedicated salt"""
        # Retrieve the encryption salt from the database
        with sqlite3.connect(self.DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT encryption_salt FROM secrets WHERE id = 1")
            result = cursor.fetchone()
            if not result:
                raise Exception("Encryption salt not found in database")
            salt_b64 = result[0]
            salt = base64.b64decode(salt_b64.encode())

        # Derive key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt, 
            iterations=600_000, 
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def _encrypt_password(self, password):
        """Encrypt a password"""
        try:
            if not self.fernet:
                raise Exception("Encryption not initialized. Please authenticate first.")
            encrypted = self.fernet.encrypt(password.encode())
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            print(f"Encryption error: {e}")
            return None

    def _decrypt_password(self, encrypted_password_b64):
        """Decrypt a password"""
        try:
            if not self.fernet:
                raise Exception("Decryption not initialized. Please authenticate first.")
            encrypted_bytes = base64.b64decode(encrypted_password_b64.encode('utf-8'))
            return self.fernet.decrypt(encrypted_bytes).decode()        
        except Exception as e:
            print(f"Decryption error: {e}")
            return None

    def authenticate(self):
        """Prompt for master password until correct"""
        while not self.is_authenticated:
            attempt = input("Enter master password: ").strip()
            
            if self._verify_master_password(attempt):
                print("Master password correct")
                self.fernet = Fernet(self._derive_key(attempt))
                self.is_authenticated = True
                return True
            else:
                print("Master password incorrect")
                print("Try again in 5 seconds")
                time.sleep(5)

    def create_master_password(self):
        """Create or generate a new master password"""
        while True:
            choice = input("Would you like to create your own master password or have us create one for you? Enter 'create' or 'generate': ").strip()
            
            if choice == "create":
                password = self._get_user_password()
                break
            elif choice == "generate":
                password = self._generate_password()
                print(f"Generated master password: {password}")
                print("Store this securely - you won't see it again!")
                break
            else:
                print("Invalid input")
        
        # Store the master password hash and salt
        self.master_hash, self.master_salt = self._hash_master_password(password)
        
        # Initialize encryption with the new password
        self.fernet = Fernet(self._derive_key(password))
        self.authenticate()

    def _validate_input(self, value, field_name):
        """Validate that input is not empty"""
        if not value or not value.strip():
            print(f"{field_name} cannot be empty.")
            return False
        return True

    def _handle_view(self):
        """View the passwords in the database"""
        with sqlite3.connect(self.DB_PATH) as connection:
            cursor = connection.cursor()
            
            try:
                cursor.execute("SELECT id, website, username, created_at FROM passwords ORDER BY created_at DESC")
                entries = cursor.fetchall()
                
                if entries:
                    print("\nStored password entries:")
                    print("-" * 50)
                    for entry in entries:
                        print(f"ID: {entry[0]} | Website: {entry[1]} | Username: {entry[2]} | Created: {entry[3]}")
                    
                    print("-" * 50)
                    selected_id = input("Enter the ID of the password you want to view: ").strip()

                    if not self._validate_input(selected_id, "ID"):
                        return

                    cursor.execute("SELECT password FROM passwords WHERE id = ?", (selected_id,))
                    result = cursor.fetchone()
                    
                    if result:
                        decrypted = self._decrypt_password(result[0])
                        if decrypted:
                            print(f"\nPassword for entry ID {selected_id}: {decrypted}")
                        else:
                            print("Failed to decrypt password.")
                    else:
                        print("No password found for that ID.")
                else:
                    print("No passwords stored yet.")

            except sqlite3.Error as e:
                print(f"Database error: {e}")

    def _handle_add(self):
        """Add a password to the database"""
        with sqlite3.connect(self.DB_PATH) as connection:
            cursor = connection.cursor()
            
            try:
                # Validate inputs
                while True:
                    website = input("Enter website: ").strip()
                    if self._validate_input(website, "Website"):
                        break

                while True:
                    username = input("Enter username: ").strip()
                    if self._validate_input(username, "Username"):
                        break

                while True:
                    choice = input("Would you like to create your own password or have us create one for you? Enter 'create' or 'generate': ").strip()
                    
                    if choice == "create":
                        password = self._get_user_password()
                        break
                    elif choice == "generate":
                        password = self._generate_password()
                        print(f"This is the generated password for {website}: {password}")
                        break
                    else:
                        print("Invalid input")
                
                encrypted_password = self._encrypt_password(password)
                if not encrypted_password:
                    print("Failed to encrypt password. Entry not saved.")
                    pass

                # Store the encrypted password in database
                cursor.execute('''INSERT INTO passwords
                                (website, username, password) 
                                VALUES (?, ?, ?)''', 
                            (website, username, encrypted_password))
                
                connection.commit()
                print("Password added successfully")

            except sqlite3.Error as e:
                print(f"Database error: {e}")

    def _handle_delete(self):
        """Delete a password from the database"""
        with sqlite3.connect(self.DB_PATH) as connection:
            cursor = connection.cursor()
            
            try:
                cursor.execute("SELECT id, website, username, created_at FROM passwords ORDER BY created_at DESC")
                entries = cursor.fetchall()
                
                if entries:
                    print("\nStored password entries:")
                    print("-" * 50)
                    for entry in entries:
                        print(f"ID: {entry[0]} | Website: {entry[1]} | Username: {entry[2]} | Created: {entry[3]}")
                    
                    print("-" * 50)

                    while True:

                        selected_id = input("Enter the ID of the password you want to delete: ").strip()

                        if not self._validate_input(selected_id, "ID"):
                            continue

                        delete_confirmation = input(f"Are you sure you want to delete ID: {selected_id}? (yes/no): ").strip()

                        if delete_confirmation == "yes":
                            cursor.execute("SELECT website FROM passwords WHERE id = ?", (selected_id,))
                            website_result = cursor.fetchone()
                            
                            if website_result:
                                website_name = website_result[0]
                                # Proceed to delete after confirming it exists
                                cursor.execute("DELETE FROM passwords WHERE id = ?", (selected_id,))
                                connection.commit()
                                print(f"\nPassword for website '{website_name}' (ID: {selected_id}) has been deleted.")
                            else:
                                print("No password found for that ID.")
                            break
                        elif delete_confirmation == "no":
                            break
                        else:
                            print("Invalid input. 'yes' or 'no' for password deletion.")
                else:
                    print("No passwords stored yet.")
            except sqlite3.Error as e:
                print(f"Database error: {e}")

    def _handle_update(self):
        """Update a password from the database"""
        with sqlite3.connect(self.DB_PATH) as connection:
            cursor = connection.cursor()
            
            try:
                cursor.execute("SELECT id, website, username, created_at FROM passwords ORDER BY created_at DESC")
                entries = cursor.fetchall()

                if entries:
                    print("\nStored password entries:")
                    print("-" * 50)
                    for entry in entries:
                        print(f"ID: {entry[0]} | Website: {entry[1]} | Username: {entry[2]} | Created: {entry[3]}")
                    
                    print("-" * 50)
                    selected_id = input("Enter the ID of the password you want to update: ").strip()

                    if not self._validate_input(selected_id, "ID"):
                        pass

                    cursor.execute("SELECT website FROM passwords WHERE id = ?", (selected_id,))
                    website_result = cursor.fetchone()
                    
                    if website_result:
                        website_name = website_result[0]

                        while True:
                            username_update_decision = input("Do you want to update the username? (yes/no): ").strip()
                            if username_update_decision == "yes":
                                while True:
                                    new_username = input(f"Enter new username for {website_name}: ").strip()
                                    if self._validate_input(new_username, "Username"):
                                        cursor.execute("UPDATE passwords SET username = ? WHERE id = ?", (new_username, selected_id,))
                                        connection.commit()
                                        print("Username updated successfully.")
                                        break
                                break
                            elif username_update_decision == "no":
                                break
                            else:
                                print("Invalid input. Enter 'yes' or 'no' to update username.")
                                continue

                        while True:
                            password_update_decision = input("Do you want to update the password? (yes/no): ").strip()
                            if password_update_decision == "yes":
                                while True:
                                    choice = input("Would you like to create your own password or have us create one for you? Enter 'create' or 'generate': ").strip()
                                
                                    if choice == "create":
                                        new_password = self._get_user_password()
                                        break
                                    elif choice == "generate":
                                        new_password = self._generate_password()
                                        print(f"This is the generated password for {website_name}: {new_password}")
                                        break
                                    else:
                                        print("Invalid input")
                                
                                encrypted_password = self._encrypt_password(new_password)
                                if encrypted_password:
                                    cursor.execute("UPDATE passwords SET password = ? WHERE id = ?", (encrypted_password, selected_id,))
                                    connection.commit()
                                    print("Password updated successfully.")
                                else:
                                    print("Failed to encrypt password. Password not updated.")
                                break
                            elif password_update_decision == "no":
                                break
                            else:
                                print("Invalid input. Enter 'yes' or 'no' to update password.")
                                continue
                    else:
                        print("No password found for that ID.")
                else:
                    print("No passwords stored yet.")  
            except sqlite3.Error as e:
                print(f"Database error: {e}")

    def run(self):
        """Main application loop"""
        print("Welcome to Password Manager")

        # Check if master password already exists
        if self._check_master_password_exists():
            print("Master password found. Please authenticate.")
            self.authenticate()
        else:
            print("No master password found. Please create one.")
            self.create_master_password()
        
        if self.is_authenticated:
            print("Access granted to password database!")

        while True:
            manager_process = input("Do you want to view, add, delete, update a password, or quit? (view/add/delete/update/quit): ").strip()

            # Select and then view a password from the database
            if manager_process == "view":
                self._handle_view()
                        
            elif manager_process == "add":
                self._handle_add()

            elif manager_process == "delete":
                self._handle_delete()

            elif manager_process == "update":
                self._handle_update()
            
            elif manager_process == "quit":
                print("Goodbye!")
                break
            else:
                print("Choose 'view', 'add', 'delete', 'update', or 'quit'")

def main():
    manager = PasswordManager()
    manager.run()

if __name__ == "__main__":
    main()