import os
import bcrypt

def encrypt_password(password):
    global hashed_password, salt
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


def enter_password():
    attempt = input("Enter current password: ")
    hashed_attempt = bcrypt.hashpw(attempt.encode('utf-8'), salt)

    if hashed_attempt == hashed_password:
        print(f"entry = {hashed_attempt} , password = {hashed_password}")
        print("password correct")
    else:
        print(f"entry = {hashed_attempt} , password = {hashed_password}")
        print("password incorrect")


def create_new():
    run = True
    while run == True: 
        creation_decision = input("Would you like to create your own password or have us create one for you? Enter 'create' or 'generate': ")
        if creation_decision == "create":
            password = input("Enter new password: ")
            encrypt_password(password)
            enter_password()
            run = False
        elif creation_decision == "generate":
            # Add password generation
            print("generate")
            run = False
        else:
            run = True


create_new()
