import os
import bcrypt

def encrypt_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password, salt


def enter_password(hashed_password, salt):
    attempt = input("Enter current password: ")
    hashed_attempt = bcrypt.hashpw(attempt.encode('utf-8'), salt)

    if hashed_attempt == hashed_password:
        print(f"entry = {hashed_attempt} , password = {hashed_password}")
        print("password correct")
    else:
        print(f"entry = {hashed_attempt} , password = {hashed_password}")
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
