import tkinter as tk
from tkinter import messagebox

import database

USER = None
USER_PASS = None
CLOSE = False
ICON = "apm_icon.ico"


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

    def update_search(self):  # Check if search box should update the password list
        return self.do_update

    def set_text(self, text, placeholder=False):
        self.do_update = False
        super().set_text(text, placeholder)
        self.do_update = True

    def show_placeholder(self, *args):
        self.do_update = False
        super().show_placeholder()
        self.do_update = True

    def remove_placeholder(self, *args):
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
    if not database.user_exists(username): return throw_error('No such user "{}"!'.format(username))

    password = password_entry.get()

    if database.validate_password(username, password):
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

    database.add_user(username, password)

    login(login_window, username_entry, password_entry)


def on_close_login(login_window):
    global CLOSE
    login_window.destroy()
    CLOSE = True


# --------------------------
# Login Window
# --------------------------


def login_menu():
    login_window = tk.Tk()
    login_window.iconbitmap(ICON)
    login_window.title("Ali's Password Manager")
    login_window.bind("<Escape>", lambda event: login_window.focus_set())

    window_width = 600
    window_height = 400

    screen_width = login_window.winfo_screenwidth()
    screen_height = login_window.winfo_screenheight()

    x = int((screen_width / 2) - (window_width / 2) - 8)
    y = int((screen_height / 2) - (window_height / 2) - 28)

    login_window.geometry(f"{window_width}x{window_height}+{x}+{y}")

    login_window.config(bg="#24252A")
    login_window.resizable(False, False)
    login_window.protocol("WM_DELETE_WINDOW", lambda: on_close_login(login_window))

    title_label = tk.Label(
        login_window,
        text="Ali's Password Manager",
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


# --------------------------
# Password List
# --------------------------


def update_password_list(password_list, search_box, scroll_cmd):
    for widget in password_list.winfo_children():
        widget.destroy()

    passwords = []
    if search_box.is_empty():
        passwords = database.get_passwords(USER, USER_PASS)
    else:
        passwords = database.get_passwords(USER, USER_PASS, search_box.get())

    for i in range(len(passwords)):
        padding = (10, 10)
        if i == 0:
            padding = (0, 10)
        elif i == len(passwords) - 1:
            padding = (10, 0)

        # Entry Frame
        entry_frame = tk.Frame(
            password_list,
            bg="#24252A",
            highlightthickness=5,
            highlightbackground="#ec0c38"
        )
        entry_frame.grid(row=i, column=0, sticky=tk.W, pady=padding)

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
        tk.Button(
            entry_frame,
            text="Toggle",
            fg="#edf0f1",
            bg="#ec0c38",
            font=("Roboto", 12, "bold"),
            relief=tk.FLAT,
            command=lambda label=password_value: label.show() if label.is_hidden() else label.hide()
        ).grid(row=1, column=3, padx=10, pady=10)

        # Remove Button
        tk.Button(
            entry_frame,
            text="Remove",
            fg="#edf0f1",
            bg="#ec0c38",
            font=("Roboto", 12, "bold"),
            relief=tk.FLAT,
            command=lambda pass_id=passwords[i][0]: remove_password(password_list, search_box, scroll_cmd, pass_id)
        ).grid(row=1, column=4, padx=10, pady=10)

    # Bind scroll command to password list and its children
    password_list.bind("<MouseWheel>", scroll_cmd)
    for entry_frame in password_list.winfo_children():  # Bind mouse wheel to all entry frames
        entry_frame.bind("<MouseWheel>", scroll_cmd)
        for widget in entry_frame.winfo_children():  # Bind mouse wheel to widgets of each entry frame
            widget.bind("<MouseWheel>", scroll_cmd)


def remove_password(password_list, search_box, scroll_cmd, password_id):
    if not database.remove_password(password_id): throw_error("Error removing password!")

    update_password_list(password_list, search_box, scroll_cmd)


def add_password(password_list, search_box, scroll_cmd, service_entry, username_entry, password_entry):
    if service_entry.is_empty(): return throw_error("You must enter a service name!")
    if username_entry.is_empty(): return throw_error("You must enter a username!")
    if password_entry.is_empty(): return throw_error("You must enter a password!")

    service = service_entry.get()
    username = username_entry.get()
    password = password_entry.get()

    if not database.add_password(USER, USER_PASS, service, username, password): throw_error("Error adding password!")
    update_password_list(password_list, search_box, scroll_cmd)

    service_entry.set_text(service_entry.placeholder, True)
    username_entry.set_text(username_entry.placeholder, True)
    password_entry.set_text(password_entry.placeholder, True)
    service_entry.focus_set()


# --------------------------
# Main Window
# --------------------------


def main_menu():
    main_window = tk.Tk()
    main_window.iconbitmap(ICON)
    main_window.title("Ali's Password Manager")
    main_window.config(bg="#24252A")
    main_window.bind("<Escape>", lambda event: main_window.focus_set())

    window_width = 1280
    window_height = 720

    screen_width = main_window.winfo_screenwidth()
    screen_height = main_window.winfo_screenheight()

    x = int((screen_width / 2) - (window_width / 2) - 8)
    y = int((screen_height / 2) - (window_height / 2) - 28)

    main_window.geometry(f"{window_width}x{window_height}+{x}+{y}")

    main_window.rowconfigure(0, weight=1)
    main_window.rowconfigure(1, weight=20)
    main_window.columnconfigure([0, 1], weight=1)

    # --------------------------
    # Top Frame
    # --------------------------

    frame_top = tk.Frame(main_window, highlightthickness=5, highlightbackground="#ec0c38", bg="#24252A")
    frame_top.grid(row=0, column=0, columnspan=2, sticky=tk.NSEW, padx=10, pady=10)
    frame_top.columnconfigure(0, weight=1)
    frame_top.rowconfigure(0, weight=1)

    # Title
    title = tk.Label(
        frame_top,
        text="Ali's Password Manager",
        fg="#ec0c38",
        bg="#24252A",
        font=("Roboto", 32, "bold")
    )
    title.grid(sticky=tk.N, pady=(20, 0))

    # Logged in as
    logged_in_as = tk.Label(
        frame_top,
        text="Logged in as: " + USER,
        fg="#edf0f1",
        bg="#24252A",
        font=("Roboto", 16, "bold")
    )
    logged_in_as.grid(sticky=tk.S, pady=(0, 20))

    # --------------------------
    # Left Frame
    # --------------------------

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

    # Search Box
    search_box = SearchEntry(
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
    search_box.grid(row=1, sticky=tk.W, pady=(10, 10), padx=(12, 0))

    # Canvas for Password List
    canvas = tk.Canvas(frame_left, bg="#24252A", highlightbackground="#24252A")
    canvas.grid(row=2, sticky=tk.NSEW, padx=(10, 40), pady=(0, 10))

    # Password List
    password_list = tk.Frame(canvas, bg="#24252A")
    password_list.bind(
        "<Configure>",
        lambda event: canvas.configure(
            scrollregion=password_list.grid_bbox("all")
        )
    )
    canvas.create_window((0, 0), window=password_list, anchor="nw")

    # Scroll Bar
    scroll_bar = tk.Scrollbar(
        frame_left,
        relief=tk.FLAT,
        command=canvas.yview
    )
    scroll_bar.grid(row=2, sticky=tk.NS + tk.E, padx=(0, 10), pady=(0, 10))
    canvas.configure(yscrollcommand=scroll_bar.set)

    # Mouse wheel scroll
    scroll_cmd = lambda event: (
        canvas.yview_scroll(int(-(event.delta / 120)), "units") if scroll_bar.get() != (0.0, 1.0) else None
    )
    canvas.bind("<MouseWheel>", scroll_cmd)

    # Search Box updates Password List
    string_var = tk.StringVar()
    string_var.trace(
        "w", lambda name, index, mode: (
            update_password_list(password_list, search_box, scroll_cmd) if search_box.update_search() else None
        )
    )
    search_box.configure(textvariable=string_var)  # By doing this, it clears the search box
    search_box.set_text(search_box.placeholder, True)  # This resets the search box to have text again

    # Update password list with initial items
    update_password_list(password_list, search_box, scroll_cmd)

    # --------------------------
    # Right Frame
    # --------------------------

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

    add_pass_cmd = lambda: (
        add_password(password_list, search_box, scroll_cmd, service_entry, username_entry, password_entry)
    )
    service_entry.bind("<Return>", lambda event: add_pass_cmd())
    username_entry.bind("<Return>", lambda event: add_pass_cmd())
    password_entry.bind("<Return>", lambda event: add_pass_cmd())

    # Add Button
    add_button = tk.Button(
        frame_right,
        text="Add Password",
        fg="#edf0f1",
        bg="#ec0c38",
        font=("Roboto", 12, "bold"),
        relief=tk.FLAT,
        command=add_pass_cmd
    )
    add_button.pack(pady=(20, 0))
    add_button.bind("<Return>", lambda event: add_pass_cmd())

    main_window.mainloop()


if __name__ == '__main__':
    database.create_database()
    while not CLOSE:
        login_menu()
