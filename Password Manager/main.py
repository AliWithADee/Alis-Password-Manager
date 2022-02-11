import tkinter as tk
from tkinter import messagebox

from database import *

USER = None
USER_PASS = None


def throw_error(message):
    messagebox.showerror("Error", message)


class EntryWithPlaceholder(tk.Entry):
    def __init__(self, master=None, placeholder="PLACEHOLDER", placeholder_color="grey", secret=False, **kw):
        super().__init__(master, kw)

        self.placeholder = placeholder
        self.placeholder_color = placeholder_color
        self.secret = secret
        self.default_color = self["fg"]

        self.bind("<FocusIn>", self.remove_placeholder)
        self.bind("<FocusOut>", self.show_placeholder)

        self.set_text(self.placeholder, True)

    def is_empty(self):
        return self['fg'] == self.placeholder_color or self.get() == ""

    def set_text(self, text, placeholder=False):
        self.delete(0, "end")

        self['show'] = ""
        if (not placeholder) and self.secret: self['show'] = "*"
        self.insert(0, text)
        self['fg'] = self.default_color
        if placeholder: self['fg'] = self.placeholder_color

    def show_placeholder(self, *args):
        if self.is_empty():
            self.set_text(self.placeholder, True)

    def remove_placeholder(self, *args):
        if self.is_empty():
            self.delete(0, "end")
            self['fg'] = self.default_color
            if self.secret: self['show'] = '*'


class SearchEntry(EntryWithPlaceholder):
    def __init__(self, master=None, placeholder="PLACEHOLDER", placeholder_color="grey", secret=False, **kw):
        super().__init__(master, placeholder, placeholder_color, secret, **kw)
        self.do_update = True

    def update_search(self):
        return self.do_update
    
    def set_text(self, text, placeholder=False):
        self.do_update = False
        super().set_text(text, placeholder)
        self.do_update = True

    def show_placeholder(self,  *args):
        self.do_update = False
        super().show_placeholder()
        self.do_update = True
    
    def remove_placeholder(self,  *args):
        self.do_update = False
        super().remove_placeholder()
        self.do_update = True


class ToggleableSecretLabel(tk.Label):
    def __init__(self, master=None, **kw):
        super().__init__(master, kw)
        self.secret = self["text"]
        self.hidden = True
        self.hide()
    
    def is_hidden(self):
        return self.hidden

    def show(self):
        self["text"] = self.secret
        self.hidden = False
    
    def hide(self):
        text = ""
        for i in range(len(self.secret)):
            text += "*"
        self["text"] = text
        self.hidden = True


def login(login_window, username_entry, password_entry):
    global USER
    global USER_PASS

    if username_entry.is_empty(): return throw_error("You must enter a username!")
    if password_entry.is_empty(): return throw_error("You must enter a password!")

    username = username_entry.get()
    if not user_exists(username): return throw_error('No such user "{}"!'.format(username))

    password = password_entry.get()

    if validate_password(username, password):
        login_window.destroy()
        USER = username
        USER_PASS = password
        main_menu()
    else:
        return throw_error("Incorrect password!")


def create_account(login_window, username_entry, password_entry):
    if username_entry.is_empty(): return throw_error("You must enter a username!")
    if password_entry.is_empty(): return throw_error("You must enter a password!")

    username = username_entry.get()
    password = password_entry.get()

    add_user(username, password)

    login(login_window, username_entry, password_entry)


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

    password_entry = EntryWithPlaceholder(
        login_window,
        placeholder="Password",
        placeholder_color="#9b0826",
        secret=True,
        fg="#ec0c38",
        insertbackground="#ec0c38",
        bg="#101113",
        font=("Roboto", 16),
        width=20,
        relief=tk.FLAT,
        justify="center"
    )
    password_entry.pack()

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
        command=lambda: create_account(login_window, username_entry, password_entry)
    )
    create_button.pack()

    login_window.mainloop()


def update_password_list(scroll_frame, search_entry):
    for widget in scroll_frame.winfo_children():
        widget.destroy()

    passwords = []
    if search_entry.is_empty(): passwords = get_passwords(USER, USER_PASS)
    else: passwords = get_passwords(USER, USER_PASS, search_entry.get())

    for i in range(len(passwords)):
        padding = (10, 10)
        if i == 0:
            padding = (0, 10)
        elif i == len(passwords) - 1:
            padding = (10, 0)

        # Entry Frame
        entry_frame = tk.Frame(
            scroll_frame,
            bg="#24252A",
            highlightthickness=5,
            highlightbackground="#ec0c38"
        )
        entry_frame.grid(row=i, sticky=tk.W, column=0, pady=padding)

        # Service Label
        tk.Label(
            entry_frame,
            text="Service",
            fg="#ec0c38",
            bg="#24252A",
            font=("Roboto", 12, "bold")

        ).grid(row=0, column=0, padx=10, pady=10)

        # Username Label
        tk.Label(
            entry_frame,
            text="Username",
            fg="#ec0c38",
            bg="#24252A",
            font=("Roboto", 12, "bold")

        ).grid(row=0, column=1, padx=10, pady=10)

        # Password Label
        tk.Label(
            entry_frame,
            text="Password",
            fg="#ec0c38",
            bg="#24252A",
            font=("Roboto", 12, "bold")

        ).grid(row=0, column=2, padx=10, pady=10)

        # Service Value
        tk.Label(
            entry_frame,
            text=passwords[i][1],
            fg="#edf0f1",
            bg="#24252A",
            font=("Roboto", 12, "bold")

        ).grid(row=1, column=0, padx=10, pady=10)

        # Username Value
        tk.Label(
            entry_frame,
            text=passwords[i][2],
            fg="#edf0f1",
            bg="#24252A",
            font=("Roboto", 12, "bold")

        ).grid(row=1, column=1, padx=10, pady=10)

        # Password Value
        password_value = ToggleableSecretLabel(
            entry_frame,
            text=passwords[i][3],
            fg="#edf0f1",
            bg="#24252A",
            font=("Roboto", 12, "bold")

        )
        password_value.grid(row=1, column=2, padx=10, pady=10)

        # Toggle Button
        toggle_button = tk.Button(
            entry_frame,
            text="Toggle",
            fg="#edf0f1",
            bg="#ec0c38",
            font=("Roboto", 12, "bold"),
            relief=tk.FLAT,
            command=lambda label=password_value: label.show() if label.is_hidden() else label.hide()
        )
        toggle_button.grid(row=1, column=3, padx=10, pady=10)

        # Remove Button
        remove_button = tk.Button(
            entry_frame,
            text="Remove",
            fg="#edf0f1",
            bg="#ec0c38",
            font=("Roboto", 12, "bold"),
            relief=tk.FLAT,
            command=lambda password_id=passwords[i][0]: remove_password(scroll_frame, search_entry, password_id)
        )
        remove_button.grid(row=1, column=4, padx=10, pady=10)


def remove_password(scroll_frame, search_entry, password_id):
    if not delete_password(password_id): throw_error("Error removing password!")

    update_password_list(scroll_frame, search_entry)


def new_password(scroll_frame, search_entry, service_entry, username_entry, password_entry):
    if service_entry.is_empty(): return throw_error("You must enter a service name!")
    if username_entry.is_empty(): return throw_error("You must enter a username!")
    if password_entry.is_empty(): return throw_error("You must enter a password!")

    service = service_entry.get()
    username = username_entry.get()
    password = password_entry.get()

    if not add_password(USER, USER_PASS, service, username, password): throw_error("Error adding password!")

    service_entry.set_text(service_entry.placeholder, True)
    username_entry.set_text(username_entry.placeholder, True)
    password_entry.set_text(password_entry.placeholder, True)

    update_password_list(scroll_frame, search_entry)


def main_menu():
    main_window = tk.Tk()
    main_window.iconbitmap("icon.ico")
    main_window.title("Ali's Password Manager")
    main_window.geometry("1280x720")
    main_window.config(bg="#24252A")

    main_window.rowconfigure(0, weight=1)
    main_window.rowconfigure(1, weight=20)
    main_window.columnconfigure([0, 1], weight=1)

    # Frame Top
    frame_top = tk.Frame(main_window, highlightthickness=5, highlightbackground="#ec0c38", bg="#24252A")
    frame_top.grid(row=0, column=0, columnspan=2, sticky=tk.NSEW, padx=10, pady=10)
    frame_top.columnconfigure(0, weight=1)
    frame_top.rowconfigure(0, weight=1)

    # Title
    title = tk.Label(
        frame_top,
        text="Main Menu",
        fg="#ec0c38",
        bg="#24252A",
        font=("Roboto", 32, "bold")
    )
    title.grid(sticky=tk.N, pady=(20, 0))

    # Logged in as
    logged_in_as = tk.Label(
        frame_top,
        text="Logged in as: " + USER,
        fg="#ec0c38",
        bg="#24252A",
        font=("Roboto", 16, "bold")
    )
    logged_in_as.grid(sticky=tk.S, pady=(0, 20))

    # Left Frame
    frame_left = tk.Frame(
        main_window,
        highlightthickness=5,
        highlightcolor="#4a4a46",
        highlightbackground="#ec0c38",
        bg="#24252A"
    )
    frame_left.grid(row=1, column=0, sticky=tk.NSEW, padx=10, pady=10)
    frame_left.columnconfigure(0, weight=1)
    frame_left.rowconfigure(0, weight=1)
    frame_left.rowconfigure(1, weight=1)
    frame_left.rowconfigure(2, weight=20)

    # Passwords Label
    passwords_label = tk.Label(
        frame_left,
        text="Passwords",
        fg="#ec0c38",
        bg="#24252A",
        font=("Roboto", 24, "bold")
    )
    passwords_label.grid(row=0, sticky=tk.NW, pady=(20, 0), padx=(8, 0))

    # Search Entry
    search_entry = SearchEntry(
        frame_left,
        placeholder="Enter a service",
        placeholder_color="#9b0826",
        fg="#ec0c38",
        insertbackground="#ec0c38",
        bg="#101113",
        font=("Roboto", 16),
        width=20,
        relief=tk.FLAT
    )
    search_entry.grid(row=1, sticky=tk.W, pady=(10, 10), padx=(12, 0))

    # Canvas
    canvas = tk.Canvas(frame_left, bg="#24252A", highlightbackground="#24252A")
    canvas.grid(row=2, sticky=tk.NSEW, padx=(10, 40), pady=(0, 10))

    # Scroll Frame
    scroll_frame = tk.Frame(
        canvas,
        bg="#24252A"
    )
    scroll_frame.bind(
        "<Configure>",
        lambda event: canvas.configure(
            scrollregion=canvas.bbox("all")
        )
    )
    canvas.bind(
        "<MouseWheel>",
        lambda event: (
            canvas.yview_scroll(int(-(event.delta / 120)), "units") if len(scroll_frame.winfo_children()) > 3 else None
        )
    )
    canvas.create_window((0, 0), window=scroll_frame, anchor="nw")

    # Scroll Bar
    scroll_bar = tk.Scrollbar(
        frame_left,
        relief=tk.FLAT,
        command=canvas.yview
    )
    scroll_bar.grid(row=2, sticky=tk.NS + tk.E, padx=(0, 10), pady=(0, 10))
    canvas.configure(yscrollcommand=scroll_bar.set)

    # String Var for Search Entry
    string_var = tk.StringVar()
    string_var.trace("w", lambda name, index, mode: (
            update_password_list(scroll_frame, search_entry) if search_entry.update_search() else None
        )
    )
    search_entry.configure(textvariable=string_var)
    search_entry.set_text(search_entry.placeholder, True)

    # Right Frame
    frame_right = tk.Frame(
        main_window,
        highlightthickness=5,
        highlightcolor="#4a4a46",
        highlightbackground="#ec0c38",
        bg="#24252A"
    )
    frame_right.grid(row=1, column=1, sticky=tk.NSEW, padx=10, pady=10)
    frame_right.columnconfigure(0, weight=1)
    frame_right.rowconfigure(0, weight=1)

    # Add Label
    tk.Label(
        frame_right,
        text="Add Password",
        fg="#ec0c38",
        bg="#24252A",
        font=("Roboto", 24, "bold")
    ).pack(pady=(20, 0))

    # Service Entry
    service_entry = EntryWithPlaceholder(
        frame_right,
        placeholder="Service",
        placeholder_color="#9b0826",
        fg="#ec0c38",
        insertbackground="#ec0c38",
        bg="#101113",
        font=("Roboto", 16),
        width=20,
        relief=tk.FLAT,
        justify="center"
    )
    service_entry.pack(pady=(20, 0))

    # Username Entry
    username_entry = EntryWithPlaceholder(
        frame_right,
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
    username_entry.pack(pady=(20, 0))

    # Password Entry
    password_entry = EntryWithPlaceholder(
        frame_right,
        placeholder="Password",
        placeholder_color="#9b0826",
        secret=True,
        fg="#ec0c38",
        insertbackground="#ec0c38",
        bg="#101113",
        font=("Roboto", 16),
        width=20,
        relief=tk.FLAT,
        justify="center"
    )
    password_entry.pack(pady=(20, 0))

    # New Button
    new_button = tk.Button(
        frame_right,
        text="New Password",
        fg="#edf0f1",
        bg="#ec0c38",
        font=("Roboto", 12, "bold"),
        relief=tk.FLAT,
        command=lambda: new_password(scroll_frame, search_entry, service_entry, username_entry, password_entry)
    )
    new_button.pack(pady=(20, 0))
    new_button.bind("<Button-1>", lambda event: main_window.focus_set())

    update_password_list(scroll_frame, search_entry)
    main_window.mainloop()


if __name__ == '__main__':
    create_database()
    login_menu()
