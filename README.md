# Vanta

> A secure and user-friendly CLI password manager.

Vanta is a command-line interface (CLI) password manager designed for secure and easy management of your login credentials. It uses strong encryption and provides a straightforward interface for viewing, adding, updating, and deleting your passwords.

![Screenshot of a Vanta](./.github/assets/screenshot-1.png)

## Features

* **Secure Encryption**: Utilizes `bcrypt` for master password hashing and `Fernet` (symmetric encryption from `cryptography` library) with a derived key for encrypting stored passwords, ensuring your sensitive data is protected.
* **Master Password Management**: Allows you to create your own master password or generate a strong, random one.
* **Intuitive CLI**: Easy-to-use command-line interface with clear prompts and command shortcuts.
* **Password Complexity Checks**: Enforces complexity requirements for user-created passwords.
* **Password Generation**: Generate strong, random passwords for your new entries.
* **Organized Storage**: Stores website, username, and encrypted password entries in a SQLite database.
* **Clear Display**: Presents your stored passwords in a readable table format.
* **Cross-Platform Compatibility**: Automatically determines and uses platform-appropriate paths for database storage.


## Installation

### Requirements

* Python 3.x
* `bcrypt`
* `cryptography`
* `rich`
* `pytest`
* `pyperclip`

You can install the required Python packages using pip:

```bash
pip install -r requirements.txt
````

## Usage

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/eelixir/vanta.git
    cd vanta
    ```

2.  **Run the password manager:**

    ```bash
    python src/main.py
    ```

### First-Time Setup

Upon the first run, Vanta will detect that no master password exists and prompt you to create one:

```
Welcome to Vanta Password Manager
No master password found. Please create one.
> Choose master password method - /create to type your own, /generate for a random one:
```

  * Type `/create` or `/c` to enter your own master password.
  * Type `/generate` or `/g` to have Vanta generate a strong, random master password for you. **Make sure to securely store this generated password as it will not be shown again.**

### Authentication

After setting up or if a master password already exists, you will be prompted to enter it to access your vault:

```
> Enter master password:
```

### Commands

Once authenticated, you will see a list of available commands:

```
  /help         all commands            /h
  /info         version details         /i
  /view         view passwords          /v
  /add          add password            /a
  /update       update password         /u
  /delete       delete password         /d
  /copy         copy to clipboard       /c
  /master       change master           /m
  /quit         quit program            /q
```

  * `/help` or `/h`: Displays the list of available commands.
  * `/info` or `/i`: Shows version details and the GitHub repository link.
  * `/view` or `/v`: Lists all your stored password entries. You can then enter an ID to view the decrypted password for that entry.
  * `/add` or `/a`: Guides you through adding a new password entry, allowing you to create your own password or generate a random one.
  * `/update` or `/u`: Allows you to select an entry by ID and update its username and/or password.
  * `/delete` or `/d`: Lets you select an entry by ID to delete it from the database after a confirmation prompt.
  * `/copy` or `/c`: Copies the most recently viewed password to your clipboard.
  * `/master` or `/m`: Allows you to change the master password.
  * `/quit` or `/q`: Exits the program.


## License

Vanta is licensed under the GNU AGPL v3.

---

<a href="https://www.producthunt.com/products/vanta-4?embed=true&utm_source=badge-featured&utm_medium=badge&utm_source=badge-vanta&#0045;4" target="_blank"><img src="https://api.producthunt.com/widgets/embed-image/v1/featured.svg?post_id=984510&theme=neutral&t=1751025536638" alt="Vanta - A&#0032;secure&#0032;and&#0032;user&#0045;friendly&#0032;CLI&#0032;password&#0032;manager | Product Hunt" style="width: 250px; height: 54px;" width="250" height="54" /></a>
