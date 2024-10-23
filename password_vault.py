# Database and password security imports
import sqlite3  # Used to interact with a SQLite database to store and retrieve password vault data
import hashlib  # Provides algorithms for securely hashing passwords

# GUI imports
from tkinter import *  # Used to build the graphical user interface (GUI) for the application
from tkinter import simpledialog  # Used for pop-up dialogs to request input from the user (e.g., username, password)

# Utility imports
from functools import partial  # Used to create partial functions, simplifying callback bindings in the GUI
import uuid  # Used to generate unique identifiers, such as recovery keys
import pyperclip  # Allows the app to copy data (like recovery keys) to the system clipboard
import base64  # Used to encode/decode binary data (for encryption purposes)

# Secure random data generation
import secrets
import string

# Imports for encryption
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

backend = default_backend()
salt = b"2444"

def kdf():
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=backend)

encryptionKey = 0

def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)

def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)


def genPassword(length: int) -> str:
    return "".join(
        (
            secrets.choice(string.ascii_letters + string.digits + string.punctuation)
            for i in range(length)
        )
    )

# Database code
with sqlite3.connect("password_vault.db") as db:
    cursor = db.cursor()

cursor.execute(
    """
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL,
recoveryKey TEXT NOT NULL);
"""
)

cursor.execute(
    """
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
"""
)

cursor.execute(
    """
CREATE TABLE IF NOT EXISTS masterkey(
id INTEGER PRIMARY KEY,
masterKeyPassword TEXT NOT NULL,
masterKeyRecoveryKey TEXT NOT NULL);
"""
)

# Function to create a pop-up dialog to get user input
def popUp(text):
    """
    Creates a pop-up dialog box that prompts the user for a string input.

    Parameters:
    text (str): The message or prompt displayed to the user in the dialog box.

    Returns:
    str: The string input entered by the user.
    """
    answer = simpledialog.askstring("Input", text)  # Displays a pop-up dialog with the provided text as the prompt
    return answer  # Returns the user's input

# Initiate window
window = Tk()
window.update()
window.title("Password Vault")

def hashPassword(input_password):
    """
    Hashes the input password using SHA-256 encryption.

    Parameters:
    input_password (str): The plain text password to be hashed.

    Returns:
    str: The SHA-256 hashed representation of the password in hexadecimal format.
    """
    # Convert the input password to a byte-like object for hashing
    hash1 = hashlib.sha256(input_password)  # Creates a SHA-256 hash object from the password
    # Convert the hash object to a readable hexadecimal string
    hash1 = hash1.hexdigest()  # Converts the hash object to a hex string
    return hash1

def firstTimeScreen(hasMasterKey=None):
    """
    Displays a screen for the user to set up their master password for the first time.

    Parameters:
    hasMasterKey (str or None): Optional parameter to check if the master key is already set (default is None).
    If provided, the user may be prompted differently based on the existence of the master key.
    """
    # Clear the existing window content
    for widget in window.winfo_children():  # Remove all existing widgets to prepare for the new screen
        widget.destroy()

    window.geometry("250x125")

    lbl = Label(window, text="Choose a Master Password")
    lbl.config(anchor=CENTER)  # Center the label text
    lbl.pack()

    # Entry field for the master password (input masked with *)
    txt = Entry(window, width=20, show="*")  # The input is hidden using the '*' character
    txt.pack()
    txt.focus()  # Automatically focus on the text field when the screen is displayed

    lbl1 = Label(window, text="Re-enter password")
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    txt1 = Entry(window, width=20, show="*")
    txt1.pack()

    def savePassword():
        """
        Saves the user's master password and generates a recovery key. 
        Updates the database with the hashed password and recovery key, 
        and encrypts the master key using both.

        This function handles the logic of checking whether the two password 
        inputs match, hashing the password, generating the recovery key, 
        and saving both securely in the database.

        If the master key already exists in the database, it will be updated with 
        the new password hash. If no master key exists, a new one will be generated 
        and encrypted with the new password and recovery key hashes.
        """
        # Check if both entered passwords match
        if txt.get() == txt1.get():  # Compare the two input fields for password confirmation

            # Remove any existing master password entry from the database
            sql = "DELETE FROM masterpassword WHERE id = 1"
            cursor.execute(sql)

            hashedPassword = hashPassword(txt.get().encode())
            # Generate a new recovery key
            key = str(uuid.uuid4().hex)  # Generates a random recovery key
            hashedRecoveryKey = hashPassword(key.encode())

            # Insert the new hashed password and recovery key into the database
            insert_password = """INSERT INTO masterpassword(password, recoveryKey) VALUES(?, ?)"""
            cursor.execute(insert_password, (hashedPassword, hashedRecoveryKey))  # Save to the database

            masterKey = hasMasterKey if hasMasterKey else genPassword(64) 
            cursor.execute("SELECT * FROM masterkey")

            if cursor.fetchall():
                cursor.execute("DELETE FROM masterkey WHERE id = 1")

            insert_masterkey = """INSERT INTO masterkey(masterKeyPassword, masterKeyRecoveryKey) VALUES(?, ?)"""
            cursor.execute(
                insert_masterkey,
                (
                    encrypt(masterKey.encode(), base64.urlsafe_b64encode(kdf().derive(txt.get().encode()))),
                    encrypt(masterKey.encode(), base64.urlsafe_b64encode(kdf().derive(key.encode()))),
                ),
            )

            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf().derive(masterKey.encode()))

            db.commit()
            recoveryScreen(key)

        else:
            lbl.config(text="Passwords don't match")

    btn = Button(window, text="Save", command=savePassword)
    btn.pack(pady=5)

def recoveryScreen(key):
    """
    Displays the recovery screen where the user is shown a generated recovery key. 
    The user can copy the key to their clipboard for future account recovery and proceed 
    to the vault screen once they are done.

    Parameters:
    key (str): The recovery key that will be displayed for the user to save.
    """
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x125")

    lbl = Label(window, text="Save this key to be able to recover your account")
    lbl.config(anchor=CENTER)
    lbl.pack()

    lbl1 = Label(window, text=key)
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    # Function to copy the recovery key to the clipboard
    def copyKey():
        """
        Copies the displayed recovery key to the user's clipboard using pyperclip.
        """
        pyperclip.copy(lbl1.cget("text"))

    btn = Button(window, text="Copy Key", command=copyKey)
    btn.pack(pady=5)

    # Function to proceed to the vault screen once the user has saved their recovery key
    def done():
        """
        Navigates the user to the vault screen after they confirm they have saved the key.
        """
        vaultScreen()

    btn = Button(window, text="Done", command=done)
    btn.pack(pady=5)

def resetScreen():
    """
    Displays the reset screen where the user can enter their recovery key to reset their master password.

    This function allows the user to input their recovery key, which is checked against the stored hashed
    recovery key in the database. If the key matches, the user is taken to the screen where they can 
    set a new master password.
    """
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x125")

    lbl = Label(window, text="Enter Recovery Key")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20)
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    def getRecoveryKey():
        """
        Hashes the recovery key entered by the user and checks it against the database.

        Returns:
        list: A list of matching records if the recovery key exists in the database; otherwise an empty list.
        """
        # Get the recovery key input from the user and hash it
        recoveryKeyCheck = hashPassword(str(txt.get()).encode())

        # Query the database to check if the hashed recovery key matches the stored recovery key
        cursor.execute(
            "SELECT * FROM masterpassword WHERE id = 1 AND recoveryKey = ?",
            [recoveryKeyCheck],
        )
        return cursor.fetchall()

    def checkRecoveryKey():
        """
        Verifies if the entered recovery key is correct. If the recovery key is valid, it decrypts the master key 
        and takes the user to the screen for resetting their master password. Otherwise, it prompts an error.
        """
        recoveryKey = getRecoveryKey()

        if recoveryKey:  # If the recovery key exists in the database
            # Fetch the encrypted master key from the database
            cursor.execute("SELECT * FROM masterkey")
            masterKeyEntry = cursor.fetchall()

            if masterKeyEntry:# If the master key exists
                # Extract and decrypt the master key using the recovery key
                masterKeyRecoveryKey = masterKeyEntry[0][2]
                masterKey = decrypt(
                    masterKeyRecoveryKey,
                    base64.urlsafe_b64encode(kdf().derive(str(txt.get()).encode()))
                ).decode()

                # Redirect the user to the first-time screen to set a new master password
                firstTimeScreen(masterKey)
            else:
                print("Master Key entry missing!")
                exit()
        else:
            # If the recovery key is incorrect, show an error and reset the input field
            txt.delete(0, "end")  # Clear the input field
            lbl1.config(text="Wrong Key")

    btn = Button(window, text="Check Key", command=checkRecoveryKey)
    btn.pack(pady=5)

def loginScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x125")

    lbl = Label(window, text="Enter  Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.config(anchor=CENTER)
    lbl1.pack(side=TOP)

    def getMasterPassword():
        """
        Retrieves the hashed password from the database for comparison with the user-provided password.

        This function hashes the user-entered password and checks the database for a match with the stored
        hashed master password.

        Returns:
        list: A list of matching records if the password exists in the database; otherwise, an empty list.
        """
        checkHashedPassword = hashPassword(txt.get().encode())

        cursor.execute(
            "SELECT * FROM masterpassword WHERE id = 1 AND password = ?",
            [checkHashedPassword],
        )
        return cursor.fetchall()

    def checkPassword():
        """
        Verifies the entered password against the stored master password.

        If the password matches, decrypts the master key and sets the global encryption key, 
        then redirects the user to the password vault screen. If the password is incorrect, 
        it displays an error and clears the input field.
        """
        password = getMasterPassword()

        if password:  # If the password exists in the database (i.e., it matches)
            # Retrieve and decrypt the master key
            cursor.execute("SELECT * FROM masterkey")
            masterKeyEntry = cursor.fetchall()

            if masterKeyEntry:  # If the master key exists in the database
                masterKeyPassword = masterKeyEntry[0][1]

                print(txt.get().encode())

                masterKey = decrypt(
                    masterKeyPassword,
                    base64.urlsafe_b64encode(kdf().derive(txt.get().encode()))
                )

                global encryptionKey
                encryptionKey = base64.urlsafe_b64encode(kdf().derive(masterKey))

                # Redirect to the password vault screen
                vaultScreen()

            else:
                print("Master Key entry missing!")
                exit()
        else:
            # If the password is incorrect, clear the input field and display an error
            txt.delete(0, "end")  # Clear the entered text
            lbl1.config(text="Wrong Password")

    def resetPassword():
        """
        Redirects the user to the password recovery screen, allowing them to reset their master password.
        """
        resetScreen()

    btn = Button(window, text="Submit", command=checkPassword)
    btn.pack(pady=5)
    btn = Button(window, text="Reset Password", command=resetPassword)
    btn.pack(pady=5)

def vaultScreen():
    """
    Displays the password vault screen after successful login. This screen allows the user to view, add, and remove
    entries from the password vault. The vault entries are encrypted and decrypted using the master encryption key.
    """
    for widget in window.winfo_children():
        widget.destroy()

    def addEntry():
        """
        Prompts the user to add a new entry (website, username, password) to the vault.
        Encrypts the input fields and saves them to the database.
        """
        # Get user input for website, username, and password
        website = encrypt(popUp("Website").encode(), encryptionKey)
        username = encrypt(popUp("Username").encode(), encryptionKey)
        password = encrypt(popUp("Password").encode(), encryptionKey)

        # Insert the encrypted data into the vault database
        insert_fields = """INSERT INTO vault(website, username, password) VALUES(?, ?, ?)"""
        cursor.execute(insert_fields, (website, username, password))
        db.commit()

        vaultScreen()  # Refresh the screen to show the updated vault

    def removeEntry(entry_id):
        """
        Removes a vault entry based on its unique identifier (id).
        
        Parameters:
        entry_id (int): The unique id of the entry to be deleted.
        """
        cursor.execute("DELETE FROM vault WHERE id = ?", (entry_id,))
        db.commit()
        vaultScreen()

    window.geometry("750x550")
    window.resizable(height=None, width=None)

    lbl = Label(window, text="Password Vault")
    lbl.grid(column=1)

    btn = Button(window, text="+", command=addEntry)
    btn.grid(column=1, pady=10)

    Label(window, text="Website").grid(row=2, column=0, padx=80)
    Label(window, text="Username").grid(row=2, column=1, padx=80)
    Label(window, text="Password").grid(row=2, column=2, padx=80)

    cursor.execute("SELECT * FROM vault")
    vault_entries = cursor.fetchall()

    if vault_entries:  # Ensure there are entries in the vault before displaying them
        for i, entry in enumerate(vault_entries):
            """
            The vault entries are displayed in rows with corresponding decrypted website, username, 
            and password fields. The ID is used for identifying which entry to delete.
            """
            # Decrypt and display the website, username, and password for each entry
            Label(window, text=decrypt(entry[1], encryptionKey), font=("Helvetica", 12)).grid(column=0, row=i + 3)
            Label(window, text=decrypt(entry[2], encryptionKey), font=("Helvetica", 12)).grid(column=1, row=i + 3)
            Label(window, text=decrypt(entry[3], encryptionKey), font=("Helvetica", 12)).grid(column=2, row=i + 3)

            btn = Button(window, text="Delete", command=partial(removeEntry, entry[0]))
            btn.grid(column=3, row=i + 3, pady=10)

cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():  # If a master password exists
    loginScreen()  # Direct the user to the login screen
else:
    firstTimeScreen()  # Direct the user to the first-time setup screen

window.mainloop()