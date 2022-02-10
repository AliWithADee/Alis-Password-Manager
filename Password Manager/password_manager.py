import sqlite3 as sql
import tkinter as tk
from tkinter import messagebox
from hashlib import sha512

FILE = "database.db"


def create_database():
    users = """
            CREATE TABLE IF NOT EXISTS tblUsers
            (username text,
            password text,
            PRIMARY KEY (username))
            """

    passwords = """
                CREATE TABLE IF NOT EXISTS tblPasswords
                (ID integer,
                user text,
                service text,
                username text,
                password text,
                PRIMARY KEY (ID)
                FOREIGN KEY (user) REFERENCES tblUsers(username))
                """

    with sql.connect(FILE) as conn:
        cursor = conn.cursor()
        cursor.execute(users)
        cursor.execute(passwords)
        conn.commit()


def throw_error(message):
    messagebox.showerror("Error", message)


def user_exists(username):
    with sql.connect(FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        SELECT username
        FROM tblUsers
        WHERE username = ?
        """, [username])
        if cursor.fetchall():
            return True

    return False


def get_encryption_key(plain_pass: str):
    return sha512(plain_pass.encode()).hexdigest()


def get_hashed_password(plain_pass: str):
    return sha512(get_encryption_key(plain_pass).encode()).hexdigest()


def add_user(username, password):
    if user_exists(username): return throw_error("User already exists!")

    with sql.connect(FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO tblUsers
        VALUES (?,?)
        """, (username, get_hashed_password(password)))


def correct_password(username, password):
    with sql.connect(FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        SELECT password
        FROM tblUsers
        WHERE username = ?
        """, [username])

        data = cursor.fetchall()
        if get_hashed_password(password) == data[0][0]:
            return True

    return False


class EntryWithPlaceholder(tk.Entry):
    def __init__(self, master=None, placeholder="PLACEHOLDER", placeholder_color="grey", **kw):
        super().__init__(master, kw)

        self.placeholder = placeholder
        self.placeholder_color = placeholder_color
        self.default_fg_color = self["fg"]

        self.bind("<FocusIn>", self.focus_in)
        self.bind("<FocusOut>", self.focus_out)

        self.put_placeholder()

    def is_empty(self):
        return self['fg'] == self.placeholder_color or self.get() == ""

    def put_placeholder(self):
        self.insert(0, self.placeholder)
        self['fg'] = self.placeholder_color

    def focus_in(self, *args):
        if self.is_empty():
            self.delete(0, "end")
            self['fg'] = self.default_fg_color

    def focus_out(self, *args):
        if self.is_empty():
            self.put_placeholder()


def login(login_window, username_entry, password_entry):
    if username_entry.is_empty(): return throw_error("You must enter a username!")
    if password_entry.is_empty(): return throw_error("You must enter a password!")

    username = username_entry.get()
    if not user_exists(username): return throw_error('No such user "{}"!'.format(username))

    password = password_entry.get()

    if correct_password(username, password):
        login_window.destroy()
        main_menu(username, password)
    else:
        return throw_error("Incorrect password!")


def create_account(username_entry, password_entry):
    if username_entry.is_empty(): return throw_error("You must enter a username!")
    if password_entry.is_empty(): return throw_error("You must enter a password!")

    username = username_entry.get()
    password = password_entry.get()

    add_user(username, password)


def login_menu():
    login_window = tk.Tk()
    login_window.iconbitmap("icon.ico")
    login_window.title("Ali's Password Manager")
    login_window.geometry("650x400")
    login_window.config(bg="#24252A")
    login_window.resizable(False, False)

    title_label = tk.Label(
        login_window,
        text="Password Manager",
        fg="#ec0c38",
        bg="#24252A",
        font=("Roboto", 24, "bold")
    )
    title_label.pack(pady=(20, 0))

    username_entry = EntryWithPlaceholder(
        login_window,
        placeholder="Username",
        placeholder_color="#9b0826",
        fg="#ec0c38",
        insertbackground="#ec0c38",
        bg="#101113",
        font=("Roboto", 16),
        width=20,
        relief=tk.FLAT,
        justify="center"
    )
    username_entry.pack(pady=40)

    username_entry.delete(0, "end")  # TODO: Debug
    username_entry.insert(0, "Ali")
    username_entry['fg'] = username_entry.default_fg_color

    password_entry = EntryWithPlaceholder(
        login_window,
        placeholder="Password",
        placeholder_color="#9b0826",
        show="*",  # TODO: Toggle with placeholder
        fg="#ec0c38",
        insertbackground="#ec0c38",
        bg="#101113",
        font=("Roboto", 16),
        width=20,
        relief=tk.FLAT,
        justify="center"
    )
    password_entry.pack()

    password_entry.delete(0, "end")  # TODO: Debug
    password_entry.insert(0, "Password")
    password_entry['fg'] = password_entry.default_fg_color

    login_button = tk.Button(
        login_window,
        text="Login",
        fg="#edf0f1",
        bg="#ec0c38",
        font=("Roboto", 18, "bold"),
        relief=tk.FLAT,
        command=lambda: login(login_window, username_entry, password_entry)
    )
    login_button.pack(pady=40)

    create_button = tk.Button(
        login_window,
        text="Create Account",
        fg="#edf0f1",
        bg="#ec0c38",
        font=("Roboto", 12, "bold"),
        relief=tk.FLAT,
        command=lambda: create_account(username_entry, password_entry)
    )
    create_button.pack()

    login_window.mainloop()


def decrypt(plain_text, key):
    return "password here 123"


def get_passwords(username, password):
    key = get_encryption_key(password)

    with sql.connect(FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        SELECT tblPasswords.service, tblPasswords.username, tblPasswords.password
        FROM tblPasswords
        WHERE tblPasswords.user = ?
        """, [username])

        data = cursor.fetchall()
        passwords = []
        for entry in data:
            password = decrypt(entry[2], key)
            passwords.append([entry[0], entry[1], password])
        return passwords


def main_menu(username, password):
    main_window = tk.Tk()
    main_window.iconbitmap("icon.ico")
    main_window.title("Ali's Password Manager")
    main_window.geometry("1280x720")
    main_window.config(bg="#24252A")

    main_window.rowconfigure(0, weight=1)
    main_window.rowconfigure(1, weight=20)
    main_window.columnconfigure([0, 1], weight=1)

    top = tk.Frame(main_window, highlightthickness=5, highlightbackground="#ec0c38", bg="#24252A")
    top.grid(row=0, column=0, columnspan=2, sticky=tk.NSEW, padx=10, pady=10)
    top.columnconfigure(0, weight=1)
    top.rowconfigure(0, weight=1)

    title = tk.Label(
        top,
        text="Main Menu",
        fg="#ec0c38",
        bg="#24252A",
        font=("Roboto", 32, "bold")
    )
    title.grid(sticky=tk.N, pady=(20, 0))

    logged_in = tk.Label(
        top,
        text="Logged in as: " + username,
        fg="#ec0c38",
        bg="#24252A",
        font=("Roboto", 16, "bold")
    )
    logged_in.grid(sticky=tk.S, pady=(0, 20))

    left = tk.Frame(main_window, highlightthickness=5, highlightcolor="#ec0c38", highlightbackground="#ec0c38",
                    bg="#24252A")
    left.grid(row=1, column=0, sticky=tk.NSEW, padx=10, pady=10)
    left.columnconfigure(0, weight=1)
    left.rowconfigure(0, weight=1)
    left.rowconfigure(1, weight=20)

    passwords_label = tk.Label(
        left,
        text="Passwords",
        fg="#ec0c38",
        bg="#24252A",
        font=("Roboto", 24, "bold")
    )
    passwords_label.grid(row=0, sticky=tk.NW, pady=(20, 0), padx=(8, 0))

    passwords_list_box = tk.Listbox(
        left,
        font=("Roboto", 18),
        width=20,
        fg="#edf0f1",
        bg="#24252A",
        borderwidth=0,
        highlightthickness=0,
        relief=tk.FLAT,
        selectmode=tk.SINGLE
    )
    passwords_list_box.grid(row=1, sticky=tk.NSEW, padx=(10, 40), pady=10)

    for v in range(5):
        passwords_list_box.insert(tk.END, "Service: Bank | Username: Ali Dee | Password: 123456")

    scroll_bar = tk.Scrollbar(
        left,
        relief=tk.FLAT
    )
    scroll_bar.grid(row=1, sticky=tk.NS + tk.E, padx=(0, 10))
    passwords_list_box.config(yscrollcommand=scroll_bar.set)
    scroll_bar.config(command=passwords_list_box.yview)

    right = tk.Frame(main_window, highlightthickness=5, highlightbackground="#ec0c38", bg="#24252A")
    right.grid(row=1, column=1, sticky=tk.NSEW, padx=10, pady=10)
    right.columnconfigure(0, weight=1)
    right.rowconfigure(0, weight=1)

    # other_label = tk.Label(
    #     right,
    #     text="Other Label",
    #     fg="#ec0c38",
    #     bg="#24252A",
    #     font=("Roboto", 24, "bold")
    # )
    # other_label.grid(sticky=tk.N, pady=(20, 0))

    main_window.mainloop()


create_database()
login_menu()
