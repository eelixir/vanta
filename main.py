import os
import hashlib

def encrypt_password(password):
    global hash_password
    hash_object = hashlib.sha256()
    hash_object.update(password.encode())
    hash_password = hash_object.hexdigest()
    return hash_password


def enter_password():
    entry = input("Enter current password: ")
    hash_object = hashlib.sha256()
    hash_object.update(entry.encode())
    hash_entry = hash_object.hexdigest()

    if hash_entry == hash_password:
        print(f"entry = {hash_entry} , password = {hash_password}")
        print("password correct")
    else:
        print(f"entry = {hash_entry} , password = {hash_password}")
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
