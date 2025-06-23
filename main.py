import bcrypt
import secrets
import string
import time
import sqlite3
import os
from cryptography.fernet import Fernet
import base64
import hashlib

# To-do
# GUI

class PasswordManager:
    def __init__(self):
        self.master_hash = None
        self.master_salt = None
        self.is_authenticated = False
        self.DB_PATH = os.path.join(os.path.dirname(__file__), "password.db")
    
    def _check_master_password_exists(self):
        """Check is a master password already exists in the database"""
        try:
            with sqlite3.connect(self.DB_PATH) as connection:
                cursor = connection.cursor()

                # Create master_password table if it doesn't exist
                master_password_table = '''CREATE TABLE IF NOT EXISTS master_password (
                    id INTEGER PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )'''
                cursor.execute(master_password_table)

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


    def _hash_master_password(self, password):
        """Hash master password with bcrypt"""
        salt = bcrypt.gensalt()

        try:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
            
            with sqlite3.connect(self.DB_PATH) as connection:
                cursor = connection.cursor()
                
                # Create table if it doesn't exist (will fail if table already exists without IF NOT EXISTS)
                master_password_table = '''CREATE TABLE IF NOT EXISTS master_password (
                    id INTEGER PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )'''

                cursor.execute(master_password_table)
                
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
        """Derive a symmetric encryption key from the master password"""
        digest = hashlib.sha256(password.encode()).digest()
        return base64.urlsafe_b64encode(digest)


    def _encrypt_password(self, password):
        """Encrypt a password"""
        try:
            encrypted = self.fernet.encrypt(password.encode())
            return encrypted
        except Exception as e:
            print(f"Encryption error: {e}")
            return None
        
    def _decrypt_password(self, encrypted_password):
        """Decrypt a password"""
        try:
            return self.fernet.decrypt(encrypted_password.encode()).decode()
        except Exception as e:
            print(f"Decryption error: {e}")
            return None


    def authenticate(self):
        """Prompt for master password until correct"""
        while not self.is_authenticated:
            attempt = input("Enter master password: ")
            
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
            choice = input("Would you like to create your own master password or have us create one for you? Enter 'create' or 'generate': ")
            
            if choice == "create":
                password = self._get_user_password()
                break
            elif choice == "generate":
                password = self._generate_password()
                print(f"This is your master password: {password}")
                break
            else:
                print("Invalid input")
        
        # Store the master password hash and salt
        self.master_hash, self.master_salt = self._hash_master_password(password)
        
        # Authenticate with the new password
        self.authenticate()
    

    def _get_user_password(self):
        """Get a user-created password that meets complexity requirements"""
        prompt = "Create password: " if self._check_master_password_exists() else "Create master password: "
        
        while True:
            password = input(prompt)
            if self._check_complexity(password):
                print("Password created successfully.")
                return password
    

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


    def run(self):
        """Main application loop"""
        print("Welcome to Password Manager")

        # Check is master password already exists
        if self._check_master_password_exists():
            print("Master password found. Please authenticate.")
            self.authenticate()

        else:
            print("No master password found. Please create one.")
            self.create_master_password()
        
        
        if self.is_authenticated:
            print("Access granted to password database!")

            with sqlite3.connect(self.DB_PATH) as connection:
                cursor = connection.cursor()
                
                try:
                    # Create table if it doesn't exist (will fail if table already exists without IF NOT EXISTS)
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
                    print(f"Database error: {e}")

        while True:
            manager_process = input("Do you want to view, add or delete a password? (view/add/delete): ")

            # Select and then view a password from the database
            if manager_process == "view":
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

                            
                            # fix: change to print plain text password rather than hash
                            cursor.execute("SELECT password FROM passwords WHERE id = ?", (selected_id,))
                            result = cursor.fetchone()
                            
                            if result:
                                decrypted = self._decrypt_password(result[0])
                                print(f"\nPassword for entry ID {selected_id}: {decrypted}")

                            else:
                                print("No password found for that ID.")

                        else:
                            print("No passwords stored yet.")
                            
                    except sqlite3.Error as e:
                        print(f"Database error: {e}")
                        
            elif manager_process == "add":
                with sqlite3.connect(self.DB_PATH) as connection:
                    cursor = connection.cursor()
                    
                    try:
                        website = input ("Enter website: ")
                        username = input("Enter username: ")

                        while True:
                            choice = input("Would you like to create your own master password or have us create one for you? Enter 'create' or 'generate': ")
                            
                            if choice == "create":
                                password = self._get_user_password()
                                break
                            elif choice == "generate":
                                password = self._generate_password()
                                print(f"This is your password: {password}")
                                break
                            else:
                                print("Invalid input")
                        
                        encrypted_password = self._encrypt_password(password)

                        # Store the hashed password in database
                        cursor.execute('''INSERT OR REPLACE INTO passwords
                                        (id, website, username, password) 
                                        VALUES (NULL, ?, ?, ?)''', 
                                    (website, username, encrypted_password.decode('utf-8')))
                        
                        connection.commit()
                        print("Password added successfully")

                    except sqlite3.Error as e:
                        print(f"Database error: {e}")

            elif manager_process == "delete":
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
                            selected_id = input("Enter the ID of the password you want to delete: ").strip()
                            
                            cursor.execute("SELECT website FROM passwords WHERE id = ?", (selected_id,))
                            website_result = cursor.fetchone()
                            
                            if website_result:
                                website_name = website_result[0]
                                # Proceed to delete after confirming it exists
                                cursor.execute("DELETE FROM passwords WHERE id = ?", (selected_id,))
                                print(f"\nPassword for website '{website_name}' (ID: {selected_id}) has been deleted.")
                            else:
                                print("No password found for that ID.")

                        else:
                            print("No passwords stored yet.")
                            
                    except sqlite3.Error as e:
                        print(f"Database error: {e}")

            else:
                print("Choose 'view', 'add' or 'delete'")

def main():
    manager = PasswordManager()
    manager.run()


if __name__ == "__main__":
    main()