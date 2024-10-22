import sqlite3, hashlib # sqlite3 is for the database, hashlib is to hash the password
from tkinter import * # tkinter is for the window

# Database code
with sqlite3.connect("password_vault.db") as db:
    cursor = db.cursor() # Cursor is what is used to controll the database

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
""")

window = Tk() # Initiate window
window.title("Password Vault")

def hashPassword(input):
    hash = hashlib.md5(input) # Takes the input text and turns it into an md5 hash
    hash = hash.hexdigest() # Turns the md5 hash back into text, so the user can read it
    return hash


def firstScreen():
    window.geometry("250x150")

    lbl = Label(window, text="Create Master Password")
    lbl.config(anchor=CENTER) # config allows everything to be in the middle
    lbl.pack()

    txt = Entry(window, width=20, show="*") # Password will be covered when the user is entering
    txt.pack()
    txt.focus() # When the program is launched the user is automatically on the text field 
    
    lbl1 = Label(window, text="Re-enter Password")
    lbl1.pack()

    txt1 = Entry(window, width=20, show="*")
    txt1.pack()
    txt1.focus()

    lbl2 = Label(window)
    lbl2.pack()

    def savePassword():
        if txt.get() == txt1.get(): # The password the user entered is equal to their password
            """
            utf-8: The program is giving hashpassword a string, but the hashing method needs the string to be encoded.
            So it wont give it pure string, it'll give it non-readable letters.
            """
            hashedPassword = hashPassword(txt.get().encode('utf-8'))
            # insert_password will add to the database the password the user entered into the text when we press submit
            insert_password = """INSERT INTO masterpassword(password) 
            VALUES(?) """
            cursor.execute(insert_password, [(hashedPassword)])
            db.commit()
            passwordVault() # When the user saves the password, program brings them to the password vault screen
        else:
            lbl2.configure(text="Passwords do not match")

    btn = Button(window, text="Save", command=savePassword)
    btn.pack(pady=10)

def loginScreen():
    window.geometry("250x100")

    lbl = Label(window, text="Enter Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus() 
    
    lbl1 = Label(window)
    lbl1.pack()

    """
    getMasterPassword will take the password the user entered while trying to login and it'll check for a match in the 
    database
    """
    def getMasterPassword():
        checkHashedPassword = hashPassword(txt.get().encode('utf-8'))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(checkHashedPassword)])
        print(checkHashedPassword)
        return cursor.fetchall()

    def checkPassword():
        match = getMasterPassword()
        print(match)

        if match: # If passwords match, program sends the user to the password vault
            passwordVault()
        else:
            txt.delete(0, 'end') # When the user types the wrong password, the text will be deleted
            lbl1.config(text="Wrong Password")

    btn = Button(window, text="Submit", command=checkPassword)
    btn.pack(pady=10)

def passwordVault(): # When the user enters the right password, they are brought to this page
    '''
    When the user switches from the login screen to the password vault, the program will destroy all the text. If not 
    it'll keep all the text and stack on top of eachother.
    '''
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("700x350")

    lbl = Label(window, text="Password Vault")
    lbl.config(anchor=CENTER) # config allows everything to be in the middle
    lbl.pack()

cursor.execute("SELECT * FROM masterpassword")

if cursor.fetchall(): # If there is a value in the master password table 
    loginScreen() # program goes directly to login screen
else:
    firstScreen() # program goes directly to login screen

window.mainloop()
