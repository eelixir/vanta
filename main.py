import bcrypt
import secrets

# To-Do
# - password generation
# - password complexity  (minimum length / complexity for created passwords)
# - brute force protection (rate limiting / delay after failed attempts)
# - error handling for encoding errors

def encrypt_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password, salt


def enter_password(hashed_password, salt):
    attempt = input("Enter current password: ")
    hashed_attempt = bcrypt.hashpw(attempt.encode('utf-8'), salt)

    if secrets.compare_digest(hashed_attempt, hashed_password) == True:
        print("password correct")
    else:
        print("password incorrect")


def create_new():
    while True: 
        creation_decision = input("Would you like to create your own password or have us create one for you? Enter 'create' or 'generate': ")
        if creation_decision == "create":
            password = input("Enter new password: ")
            hashed_password, salt = encrypt_password(password)
            enter_password(hashed_password, salt)
            break
        elif creation_decision == "generate":
            # Add password generation
            print("generate")
            break
        else:
            print("invalid input")


create_new()
