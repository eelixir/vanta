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
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.align import Align
import platform

# To-do
# Add ability to go back at anytime
# entropy visualiser
# add secure deletion with overwrites

class PasswordManager:
    def __init__(self):
        self.version = "0.2.0"
        self.console = Console()
        self.master_hash = None
        self.is_authenticated = False
        self.fernet = None  
        self.DB_PATH = self._get_database_path()
        
        self._initialize_database() 

    def _get_database_path(self):
        """Get platform-appropriate database path"""
        app_name = "Vanta"
        db_filename = "vault.db"
        
        system = platform.system()
        
        if system == "Windows":
            try:
                documents_path = os.path.expanduser('~/Documents')
                if os.path.exists(documents_path) and os.access(documents_path, os.W_OK):
                    base_path = documents_path
                else:
                    raise OSError("Documents folder not accessible")
            except OSError:
                try:
                    user_profile = os.environ.get('USERPROFILE')
                    if user_profile:
                        base_path = os.path.join(user_profile, 'AppData', 'Roaming')
                    else:
                        base_path = os.path.expanduser('~\\AppData\\Roaming')
                    
                    if not os.access(base_path, os.W_OK):
                        raise OSError("AppData not writable")
                        
                except OSError:
                    print("Warning: Using current directory for database storage")
                    return os.path.join(os.getcwd(), db_filename)
                    
        elif system == "Darwin":  # macOS
            base_path = os.path.expanduser('~/Library/Application Support')
        else:  # Linux and other Unix-like systems
            base_path = os.environ.get('XDG_DATA_HOME')
            if not base_path:
                base_path = os.path.expanduser('~/.local/share')
        
        app_dir = os.path.join(base_path, app_name)
        
        try:
            os.makedirs(app_dir, exist_ok=True)
            
            test_file = os.path.join(app_dir, '.write_test')
            try:
                with open(test_file, 'w') as f:
                    f.write('test')
                os.remove(test_file)
            except OSError:
                raise OSError("Cannot write to app directory")
                
        except OSError as e:
            print(f"Warning: Could not create app directory {app_dir}: {e}")
            fallback_path = os.path.join(os.getcwd(), db_filename)
            print(f"Using fallback location: {fallback_path}")
            return fallback_path
        
        return os.path.join(app_dir, db_filename)
    
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
                    password_hash BLOB NOT NULL,
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
            print(f"Database initialization error: {e}\n")

    def _check_master_password_exists(self):
        """Check if a master password already exists in the database"""
        try:
            with sqlite3.connect(self.DB_PATH) as connection:
                cursor = connection.cursor()

                # Check if master password exists
                cursor.execute("SELECT password_hash FROM master_password WHERE id = 1")
                result = cursor.fetchone()

                if result:
                    self.master_hash = result[0]
                    return True
                else:
                    return False
                
        except sqlite3.Error as e:
            print(f"Database error: {e}\n")
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
            password = self.console.input(f"[yellow]> [/yellow]{prompt}").strip()
            if self._check_complexity(password):
                print("Password created successfully.")
                return password

    def _hash_master_password(self, password):
        """Hash master password with bcrypt"""
        try:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            with sqlite3.connect(self.DB_PATH) as connection:
                cursor = connection.cursor()
                
                # Store the hashed password in database 
                cursor.execute('''INSERT OR REPLACE INTO master_password 
                                (id, password_hash) 
                                VALUES (1, ?)''', 
                            (hashed_password,))
                
                connection.commit()       
                     
            return hashed_password

        except sqlite3.Error as e:
            print(f"Database error: {e}\n")
            return None
        
        except UnicodeEncodeError:
            print("Encoding error. Please try again with valid characters.")
            return None, None

    def _verify_master_password(self, attempt):
        """Verify an attempted master password"""
        try:
            return bcrypt.checkpw(attempt.encode('utf-8'), self.master_hash)
        
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
            attempt = self.console.input("[yellow]> [/yellow]Enter master password: ").strip()
            
            if attempt == "/quit" or attempt == "/q":
                print("Goodbye, friend.")
                exit()
            elif self._verify_master_password(attempt):
                print("Master password correct")
                self.fernet = Fernet(self._derive_key(attempt))
                self.is_authenticated = True
                return True
            else:
                self.console.print("Incorrect master password. Access denied.", style="red")
                print("Try again in 5 seconds...\n")
                time.sleep(5)

    def create_master_password(self):
        """Create or generate a new master password"""
        while True:
            choice = self.console.input("[yellow]> [/yellow]Choose master password method - /create to type your own, /generate for a random one: ").strip()
            
            if choice == "/create" or choice == "/c":
                password = self._get_user_password()
                break
            elif choice == "/generate" or choice == "/g":
                while True:
                    length = int(self.console.input("[yellow]> [/yellow]Enter password length (min 16): "))

                    if length < 16:
                        print("Password must be atleast 16 characters.")
                    else:
                        password = self._generate_password(length)
                        print(f"\nGenerated master password: {password}")
                        print("Store this securely - you won't see it again!\n")
                        break
                break
            else:
                self.console.print("Invalid input. Enter '/create' or '/generate'", style="red")
        
        # Store the master password hash and salt
        self.master_hash= self._hash_master_password(password)
        
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
                    table = Table(title="\nStored password entries")
                    table.add_column("ID", justify="center", style="cyan", no_wrap=True)
                    table.add_column("Website", justify="center", style="cyan", no_wrap=True)
                    table.add_column("Username", justify="center", style="cyan", no_wrap=True)
                    table.add_column("Creation Date", justify="center", style="cyan", no_wrap=True)

                    for entry in entries:
                        table.add_row(f"{entry[0]}", f"{entry[1]}", f"{entry[2]}", f"{entry[3]}")
                    
                    self.console.print(table)
                    print("")

                    selected_id = self.console.input("[yellow]> [/yellow]Enter the ID of the password you want to view: ").strip()

                    if not self._validate_input(selected_id, "ID"):
                        print("")
                        return

                    cursor.execute("SELECT password FROM passwords WHERE id = ?", (selected_id,))
                    result = cursor.fetchone()
                    
                    if result:
                        decrypted = self._decrypt_password(result[0])
                        if decrypted:
                            print(f"Password for entry ID {selected_id}: {decrypted}\n")
                        else:
                            print("Failed to decrypt password.\n")
                    else:
                        print("No password found for that ID.\n")
                else:
                    print("No passwords stored yet.\n")

            except sqlite3.Error as e:
                print(f"Database error: {e}\n")

    def _handle_add(self):
        """Add a password to the database"""
        with sqlite3.connect(self.DB_PATH) as connection:
            cursor = connection.cursor()
            
            try:
                # Validate inputs
                while True:
                    website = self.console.input("[yellow]> [/yellow]Enter website: ").strip()
                    if self._validate_input(website, "Website"):
                        break

                while True:
                    username = self.console.input("[yellow]> [/yellow]Enter username: ").strip()
                    if self._validate_input(username, "Username"):
                        break

                while True:
                    choice = self.console.input("[yellow]> [/yellow]Choose password method - /create to type your own, /generate for a random one: ").strip()
                    
                    if choice == "/create" or choice == "/c":
                        password = self._get_user_password()
                        break
                    elif choice == "/generate" or choice == "/g":
                        while True:
                            length = int(self.console.input("[yellow]> [/yellow]Enter password length (min 16): "))

                            if length < 16:
                                print("Password must be atleast 16 characters.")
                            else:
                                password = self._generate_password(length)
                                print(f"This is the generated password for {website}: {password}")
                                break
                        break
                    else:
                        self.console.print("Invalid input. Enter '/create' or '/generate'", style="red")
                
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
                print("Password added successfully.\n")

            except sqlite3.Error as e:
                print(f"Database error: {e}\n")

    def _handle_update(self):
        """Update a password from the database"""
        with sqlite3.connect(self.DB_PATH) as connection:
            cursor = connection.cursor()
            
            try:
                cursor.execute("SELECT id, website, username, created_at FROM passwords ORDER BY created_at DESC")
                entries = cursor.fetchall()

                if entries:
                    table = Table(title="\nStored password entries")
                    table.add_column("ID", justify="center", style="cyan", no_wrap=True)
                    table.add_column("Website", justify="center", style="cyan", no_wrap=True)
                    table.add_column("Username", justify="center", style="cyan", no_wrap=True)
                    table.add_column("Creation Date", justify="center", style="cyan", no_wrap=True)

                    for entry in entries:
                        table.add_row(f"{entry[0]}", f"{entry[1]}", f"{entry[2]}", f"{entry[3]}")
                    
                    self.console.print(table)
                    print("")

                    selected_id = self.console.input("[yellow]> [/yellow]Enter the ID of the password you want to update: ").strip()

                    if not self._validate_input(selected_id, "ID"):
                        pass

                    cursor.execute("SELECT website FROM passwords WHERE id = ?", (selected_id,))
                    website_result = cursor.fetchone()
                    
                    if website_result:
                        website_name = website_result[0]

                        while True:
                            username_update_decision = self.console.input("[yellow]> [/yellow]Do you want to update the username? (yes/no): ").strip()
                            if username_update_decision == "yes":
                                while True:
                                    new_username = self.console.input(f"[yellow]> [/yellow]Enter new username for {website_name}: ").strip()
                                    if self._validate_input(new_username, "Username"):
                                        cursor.execute("UPDATE passwords SET username = ? WHERE id = ?", (new_username, selected_id,))
                                        connection.commit()
                                        print("Username updated successfully.")
                                        break
                                break
                            elif username_update_decision == "no":
                                break
                            else:
                                self.console.print("Invalid input. Enter 'yes' or 'no' to update username.", style="red")
                                continue

                        while True:
                            password_update_decision = self.console.input("[yellow]> [/yellow]Do you want to update the password? (yes/no): ").strip()
                            if password_update_decision == "yes":
                                while True:
                                    choice = self.console.input("[yellow]> [/yellow]Choose password method - /create to type your own, /generate for a random one: ").strip()
                                
                                    if choice == "/create" or choice == "/c":
                                        new_password = self._get_user_password()
                                        break
                                    elif choice == "/generate" or choice == "/g":
                                        while True:
                                            length = int(self.console.input("[yellow]> [/yellow]Enter password length (min 16): "))

                                            if length < 16:
                                                print("Password must be atleast 16 characters.")
                                            else:
                                                new_password = self._generate_password(length)
                                                print(f"This is the generated password for {website_name}: {new_password}")
                                                break
                                        break
                                    else:
                                        self.console.print("Invalid input. Enter '/create' or '/generate'", style="red")
                                
                                encrypted_password = self._encrypt_password(new_password)
                                if encrypted_password:
                                    cursor.execute("UPDATE passwords SET password = ? WHERE id = ?", (encrypted_password, selected_id,))
                                    connection.commit()
                                    print("Password updated successfully.")
                                else:
                                    print("Failed to encrypt password. Password not updated.\n")
                                break
                            elif password_update_decision == "no":
                                break
                            else:
                                self.console.print("Invalid input. Enter 'yes' or 'no' to update password.", style="red")
                                continue
                            
                        print(f"Update for ID {selected_id} complete.\n")

                    else:
                        print("No password found for that ID.\n")
                else:
                    print("No passwords stored yet.\n")  
            except sqlite3.Error as e:
                print(f"Database error: {e}\n")

    def _handle_master(self):
        """Change master password"""
        with sqlite3.connect(self.DB_PATH) as connection:
            cursor = connection.cursor()
            try:
                old_fernet = self.fernet

                # Fetch and decrypt with old key
                cursor.execute("SELECT id, password FROM passwords")
                all_passwords = cursor.fetchall()

                decrypted_passwords = []
                for pw_id, encrypted_pw_b64 in all_passwords:
                    try:
                        # Temporarily use old_fernet for decryption
                        encrypted_bytes = base64.b64decode(encrypted_pw_b64.encode('utf-8'))
                        decrypted = old_fernet.decrypt(encrypted_bytes).decode()
                        if decrypted:
                            decrypted_passwords.append((pw_id, decrypted))
                        else:
                            print(f"Failed to decrypt password for ID {pw_id} with old master key.")
                    except Exception as e:
                        print(f"Error decrypting password ID {pw_id}: {e}")


                self.create_master_password() 

                if not self.is_authenticated or not self.fernet:
                    print("Master password change failed or was cancelled. Aborting re-encryption.")
                    return

                # Re-encrypt and update
                for pw_id, decrypted in decrypted_passwords:
                    re_encrypted = self._encrypt_password(decrypted) 
                    if re_encrypted:
                        cursor.execute("UPDATE passwords SET password = ? WHERE id = ?", (re_encrypted, pw_id))
                    else:
                        print(f"Failed to re-encrypt password for ID {pw_id}. Data might be inconsistent.")

                connection.commit()
            except sqlite3.Error as e:
                print(f"Database error: {e}\n")



    def _handle_delete(self):
        """Delete a password from the database"""
        with sqlite3.connect(self.DB_PATH) as connection:
            cursor = connection.cursor()
            
            try:
                cursor.execute("SELECT id, website, username, created_at FROM passwords ORDER BY created_at DESC")
                entries = cursor.fetchall()
                
                if entries:
                    table = Table(title="\nStored password entries")
                    table.add_column("ID", justify="center", style="cyan", no_wrap=True)
                    table.add_column("Website", justify="center", style="cyan", no_wrap=True)
                    table.add_column("Username", justify="center", style="cyan", no_wrap=True)
                    table.add_column("Creation Date", justify="center", style="cyan", no_wrap=True)

                    for entry in entries:
                        table.add_row(f"{entry[0]}", f"{entry[1]}", f"{entry[2]}", f"{entry[3]}")
                    
                    self.console.print(table)
                    print("")

                    while True:

                        selected_id = self.console.input("[yellow]> [/yellow]Enter the ID of the password you want to delete: ").strip()

                        if not self._validate_input(selected_id, "ID"):
                            continue

                        delete_confirmation = self.console.input(f"[yellow]> [/yellow][red]Are you sure you want to delete ID: {selected_id}? (Y/n): [/red]").strip()

                        if delete_confirmation == "Y":
                            cursor.execute("SELECT website FROM passwords WHERE id = ?", (selected_id,))
                            website_result = cursor.fetchone()
                            
                            if website_result:
                                website_name = website_result[0]
                                # Proceed to delete after confirming it exists
                                cursor.execute("DELETE FROM passwords WHERE id = ?", (selected_id,))
                                connection.commit()
                                print(f"Password for website '{website_name}' (ID: {selected_id}) has been deleted.\n")
                            else:
                                print("No password found for that ID.\n")
                            break
                        elif delete_confirmation == "n":
                            break
                        else:
                            self.console.print("Invalid input. 'yes' or 'no' for password deletion.", style="red")
                else:
                    print("No passwords stored yet.\n")
            except sqlite3.Error as e:
                print(f"Database error: {e}\n")

    def startup_text(self):
        console = Console()
        console.clear()

        header = Text()
        header.append("vanta", style="bold white")
        header.append("\n")
        header.append(f"v{self.version}", style="dim white")
        
        console.print()
        console.print(Align.center(header))
        console.print()

        self.show_help()

    def show_help(self):
        console = Console()

        table = Table(show_header=False, show_lines=False, box=None, padding=(0, 2))
        table.add_column("Command", style="dim white", width=17)
        table.add_column("Description", style="white", width=20)
        table.add_column("Shortcut", style="dim white", width=10)
        
        commands = [
            ("/help", "show help", "/h"),
            ("/info", "version details", "/i"),
            ("/view", "view passwords", "/v"),
            ("/add", "add password", "/a"),
            ("/update", "update password", "/u"),
            ("/delete", "delete password", "/d"),
            ("/master", "change master", "/m"),
            ("/quit", "quit program", "/q"),
        ]
        
        for cmd, desc, shortcut in commands:
            table.add_row(cmd, desc, shortcut)
        
        print("")
        console.print(Align.center(table))
        console.print()

    def show_info(self):
        console = Console()
        print(""" 
██    ██  █████  ███    ██ ████████  █████  
██    ██ ██   ██ ████   ██    ██    ██   ██ 
██    ██ ███████ ██ ██  ██    ██    ███████ 
 ██  ██  ██   ██ ██  ██ ██    ██    ██   ██ 
  ████   ██   ██ ██   ████    ██    ██   ██                                            
        """)
        
        self.console.print(f"Version: {self.version}", style="cyan")
        console.print("Repo: [link=https://github.com/eelixir/vanta]github.com/eelixir/vanta[/link]\n", style="cyan")

    def run(self):
        """Main application loop"""
        console = Console()

        console.print("Welcome to Vanta Password Manager", style="green")

        # Check if master password already exists
        if self._check_master_password_exists():
            self.authenticate()
        else:
            print("No master password found. Please create one.")
            self.create_master_password()
        
        if self.is_authenticated:
            console.clear()
            self.startup_text()
            console.print("Access granted to password database!", style="green")

        while True:
            manager_process = console.input("[yellow]> [/yellow]").strip()

            # Select and then view a password from the database
            if manager_process == "/help" or manager_process == "/h":
                self.show_help()

            if manager_process == "/info" or manager_process == "/i":
                self.show_info()

            elif manager_process == "/view" or manager_process == "/v":
                self._handle_view()
                        
            elif manager_process == "/add" or manager_process == "/a":
                self._handle_add()

            elif manager_process == "/update" or manager_process == "/u":
                self._handle_update()

            elif manager_process == "/delete" or manager_process == "/d":
                self._handle_delete()

            elif manager_process == "/master" or manager_process == "/m":
                self._handle_master()
            
            elif manager_process == "/quit" or manager_process == "/q":
                print("Goodbye, friend.")
                break
            else:
                pass

def main():
    manager = PasswordManager()
    manager.run()

if __name__ == "__main__":
    main()