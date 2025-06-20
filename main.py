import bcrypt
import secrets
import string
from getpass import getpass

# To-Do
# - brute force protection (rate limiting / delay after failed attempts)

def encrypt_password(password):
    salt = bcrypt.gensalt()
    try:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    except UnicodeEncodeError:
        print("Encoding error. Please try again with valid characters.")
        return None, None
    return hashed_password, salt


def enter_master_password(hashed_password, salt):
    attempt = input("Enter master password: ")
    try:
        hashed_attempt = bcrypt.hashpw(attempt.encode('utf-8'), salt)
    except UnicodeEncodeError:
        print("Encoding error. Please try again with valid characters.")
        return None, None

    if secrets.compare_digest(hashed_attempt, hashed_password) == True:
        print("master password correct")
    else:
        print("master password incorrect")


def create_master_password():
    while True: 
        creation_decision = input("Would you like to create your own master password or have us create one for you? Enter 'create' or 'generate': ")

        if creation_decision == "create":
            while True:
                password = input("Create master password: ")

                if complexity_check(password):
                    print("Password created successfully.")
                    break
                else:
                    pass

            hashed_password, salt = encrypt_password(password)
            enter_master_password(hashed_password, salt)
            return False
        
        elif creation_decision == "generate":
            password = generate_password()
            print(f"This is your master password: {password}")

            hashed_password, salt = encrypt_password(password)
            enter_master_password(hashed_password, salt)
            return False
        
        else:
            print("invalid input")


def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))


def complexity_check(password):
    valid = True

    if len(password) < 12:
        print("Password must be at least 12 characters.")
        valid = False

    if not any(c.isupper() for c in password):
        print("Password must contain uppercase.")
        valid = False

    if not any(c.islower() for c in password):
        print("Password must contain lowercase.")
        valid = False

    if not any(c.isdigit() for c in password):
        print("Password must contain digits.")
        valid = False

    if not any(c in string.punctuation for c in password):
        print("Password must contain symbols.")
        valid = False

    return valid

    
def main():
    create_master_password()

if __name__ == "__main__":
    main()