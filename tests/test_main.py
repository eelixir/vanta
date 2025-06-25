import pytest
import os
import sqlite3
from unittest.mock import patch
from src.main import PasswordManager

class TestPasswordManager:
    
    @pytest.fixture
    def temp_db(self):
        """Create a temporary database for testing"""
        import tempfile
        import shutil
        
        # Create temporary directory
        temp_dir = tempfile.mkdtemp()
        db_path = os.path.join(temp_dir, "test_password.db")
        yield db_path
        
        # Force close any remaining SQLite connections
        import gc
        gc.collect()
        
        # Cleanup 
        try:
            shutil.rmtree(temp_dir)
        except PermissionError:
            import time
            time.sleep(0.1)
            try:
                shutil.rmtree(temp_dir)
            except PermissionError:
                pass
    
    @pytest.fixture
    def password_manager(self, temp_db):
        """Create a PasswordManager instance with temporary database"""
        pm = PasswordManager()
        pm.DB_PATH = temp_db
        pm._initialize_database()
        yield pm
        
        # Ensure all database connections are closed
        if hasattr(pm, '_connection') and pm._connection:
            pm._connection.close()
        
        # Force garbage collection to close any lingering connections
        import gc
        gc.collect()

    def test_password_manager_initialization(self, password_manager):
        """Test that PasswordManager initializes correctly"""
        assert password_manager.master_hash is None
        assert password_manager.is_authenticated is False
        assert password_manager.fernet is None
        assert os.path.exists(password_manager.DB_PATH)

    def test_database_initialization(self, password_manager):
        """Test that database tables are created correctly"""
        connection = None
        try:
            connection = sqlite3.connect(password_manager.DB_PATH)
            cursor = connection.cursor()
            
            # Check if tables exist
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            assert 'secrets' in tables
            assert 'master_password' in tables
            assert 'passwords' in tables
            
            # Check if encryption salt is initialized
            cursor.execute("SELECT encryption_salt FROM secrets WHERE id = 1")
            salt = cursor.fetchone()
            assert salt is not None
            assert len(salt[0]) > 0
        finally:
            if connection:
                connection.close()

    def test_generate_password_default_length(self, password_manager):
        """Test password generation with default length"""
        password = password_manager._generate_password()
        assert len(password) == 16
        assert isinstance(password, str)

    def test_generate_password_custom_length(self, password_manager):
        """Test password generation with custom length"""
        password = password_manager._generate_password(length=20)
        assert len(password) == 20

    def test_check_complexity_valid_password(self, password_manager):
        """Test complexity check with valid password"""
        valid_password = "SecurePass123!"
        assert password_manager._check_complexity(valid_password) is True

    def test_check_complexity_invalid_passwords(self, password_manager):
        """Test complexity check with various invalid passwords"""
        invalid_passwords = [
            "short",  # Too short
            "nouppercase123!",  # No uppercase
            "NOLOWERCASE123!",  # No lowercase
            "NoNumbers!",  # No digits
            "NoSymbols123",  # No symbols
        ]
        
        for password in invalid_passwords:
            assert password_manager._check_complexity(password) is False

    def test_hash_master_password(self, password_manager):
        """Test master password hashing"""
        password = "TestMasterPass123!"
        hashed = password_manager._hash_master_password(password)
        
        assert hashed is not None
        assert isinstance(hashed, bytes)
        assert len(hashed) > 0
        
        # Check if it's stored in database
        connection = None
        try:
            connection = sqlite3.connect(password_manager.DB_PATH)
            cursor = connection.cursor()
            cursor.execute("SELECT password_hash FROM master_password WHERE id = 1")
            stored_hash = cursor.fetchone()
            assert stored_hash is not None
            assert stored_hash[0] == hashed
        finally:
            if connection:
                connection.close()

    def test_verify_master_password(self, password_manager):
        """Test master password verification"""
        password = "TestMasterPass123!"
        password_manager._hash_master_password(password)
        password_manager._check_master_password_exists()
        
        # Test correct password
        assert password_manager._verify_master_password(password) is True
        
        # Test incorrect password
        assert password_manager._verify_master_password("WrongPassword") is False

    def test_derive_key(self, password_manager):
        """Test encryption key derivation"""
        password = "TestPassword123!"
        key = password_manager._derive_key(password)
        
        assert key is not None
        assert isinstance(key, bytes)
        assert len(key) == 44  

        # Same password should generate same key
        key2 = password_manager._derive_key(password)
        assert key == key2

    def test_encrypt_decrypt_password(self, password_manager):
        """Test password encryption and decryption"""
        # Setup encryption
        master_password = "MasterPass123!"
        password_manager.fernet = password_manager._derive_key(master_password)
        from cryptography.fernet import Fernet
        password_manager.fernet = Fernet(password_manager.fernet)
        
        # Test encryption/decryption
        original_password = "MySecretPass123!"
        encrypted = password_manager._encrypt_password(original_password)
        
        assert encrypted is not None
        assert isinstance(encrypted, str)
        assert encrypted != original_password
        
        # Test decryption
        decrypted = password_manager._decrypt_password(encrypted)
        assert decrypted == original_password

    def test_validate_input(self, password_manager):
        """Test input validation"""
        # Valid inputs
        assert password_manager._validate_input("valid_input", "Test Field") is True
        assert password_manager._validate_input("  valid_input  ", "Test Field") is True
        
        # Invalid inputs
        assert password_manager._validate_input("", "Test Field") is False
        assert password_manager._validate_input("   ", "Test Field") is False
        assert password_manager._validate_input(None, "Test Field") is False

    @patch('builtins.input')
    def test_get_user_password_valid(self, mock_input, password_manager):
        """Test getting user password with valid input"""
        mock_input.return_value = "ValidPassword123!"
        
        password = password_manager._get_user_password()
        assert password == "ValidPassword123!"

    @patch('builtins.input')
    @patch('builtins.print')
    def test_get_user_password_invalid_then_valid(self, mock_print, mock_input, password_manager):
        """Test getting user password with invalid then valid input"""
        # First call returns invalid password, second call returns valid
        mock_input.side_effect = ["weak", "ValidPassword123!"]
        
        password = password_manager._get_user_password()
        assert password == "ValidPassword123!"
        
        # Should have printed complexity error
        mock_print.assert_called()

    def test_check_master_password_exists_false(self, password_manager):
        """Test checking master password when it doesn't exist"""
        assert password_manager._check_master_password_exists() is False

    def test_check_master_password_exists_true(self, password_manager):
        """Test checking master password when it exists"""
        password_manager._hash_master_password("TestPassword123!")
        assert password_manager._check_master_password_exists() is True
        assert password_manager.master_hash is not None

    @patch('builtins.input')
    def test_authenticate_success(self, mock_input, password_manager):
        """Test successful authentication"""
        master_password = "MasterPass123!"
        password_manager._hash_master_password(master_password)
        password_manager._check_master_password_exists()
        
        mock_input.return_value = master_password
        
        result = password_manager.authenticate()
        assert result is True
        assert password_manager.is_authenticated is True
        assert password_manager.fernet is not None

    @patch('builtins.input')
    @patch('time.sleep')  
    def test_authenticate_failure_then_success(self, mock_sleep, mock_input, password_manager):
        """Test authentication with wrong password then correct password"""
        master_password = "MasterPass123!"
        password_manager._hash_master_password(master_password)
        password_manager._check_master_password_exists()
        
        # First attempt wrong, second attempt correct
        mock_input.side_effect = ["WrongPassword", master_password]
        
        result = password_manager.authenticate()
        assert result is True
        assert password_manager.is_authenticated is True
        assert mock_sleep.called 


# Integration tests for database operations
class TestPasswordManagerDatabase:
    
    @pytest.fixture
    def temp_db(self):
        """Create a temporary database for testing"""
        import tempfile
        import shutil
        
        # Create temporary directory
        temp_dir = tempfile.mkdtemp()
        db_path = os.path.join(temp_dir, "test_password.db")
        yield db_path
        
        # Force close any remaining SQLite connections
        import gc
        gc.collect()
        
        # Cleanup
        try:
            shutil.rmtree(temp_dir)
        except PermissionError:

            import time
            time.sleep(0.1)
            try:
                shutil.rmtree(temp_dir)
            except PermissionError:
                pass

    @pytest.fixture
    def authenticated_manager(self, temp_db):
        """Create an authenticated password manager"""
        pm = PasswordManager()
        pm.DB_PATH = temp_db
        pm._initialize_database()
        
        # Set up master password
        master_password = "MasterPass123!"
        pm._hash_master_password(master_password)
        pm._check_master_password_exists()
        pm.fernet = pm._derive_key(master_password)
        from cryptography.fernet import Fernet
        pm.fernet = Fernet(pm.fernet)
        pm.is_authenticated = True
        
        yield pm
        
        # Cleanup database connections
        if hasattr(pm, '_connection') and pm._connection:
            pm._connection.close()
        import gc
        gc.collect()

    def test_add_and_view_password(self, authenticated_manager):
        """Test adding and viewing passwords"""
        # Add a password entry directly to database
        website = "example.com"
        username = "testuser"
        password = "TestPass123!"
        
        encrypted_password = authenticated_manager._encrypt_password(password)
        
        connection = None
        try:
            connection = sqlite3.connect(authenticated_manager.DB_PATH)
            cursor = connection.cursor()
            cursor.execute('''INSERT INTO passwords (website, username, password) 
                            VALUES (?, ?, ?)''', 
                         (website, username, encrypted_password))
            connection.commit()
            
            # Verify it was stored and can be decrypted
            cursor.execute("SELECT website, username, password FROM passwords WHERE website = ?", 
                         (website,))
            result = cursor.fetchone()
            
            assert result is not None
            assert result[0] == website
            assert result[1] == username
            
            decrypted_password = authenticated_manager._decrypt_password(result[2])
            assert decrypted_password == password
        finally:
            if connection:
                connection.close()


if __name__ == "__main__":
    pytest.main([__file__])