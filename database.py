import sqlite3 as sql

import security


FILE = "apm_database.db"


def create_database():
    users = """
            CREATE TABLE IF NOT EXISTS tblUsers
            (user text,
            password text,
            PRIMARY KEY (user))
            """

    passwords = """
                CREATE TABLE IF NOT EXISTS tblPasswords
                (ID text,
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


def user_exists(user):
    with sql.connect(FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        SELECT user
        FROM tblUsers
        WHERE user = ?
        """, [user])
        if cursor.fetchall():
            return True

    return False


def password_exists(password_id):
    with sql.connect(FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        SELECT ID
        FROM tblPasswords
        WHERE ID = ?
        """, [password_id])
        if cursor.fetchall():
            return True

    return False


def add_user(user, password):
    if user_exists(user): return False

    with sql.connect(FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO tblUsers
        VALUES (?,?)
        """, (user, security.password_hashed_twice(password)))

    return True


def validate_password(user, password):
    with sql.connect(FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        SELECT password
        FROM tblUsers
        WHERE user = ?
        """, [user])

        data = cursor.fetchall()
        if security.password_hashed_twice(password) == data[0][0]:
            return True

    return False


def get_passwords(user, user_password, search=None):
    if search:
        with sql.connect(FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT tblPasswords.ID, tblPasswords.service, tblPasswords.username, tblPasswords.password
            FROM tblPasswords
            WHERE tblPasswords.user = ? AND tblPasswords.service LIKE {}
            ORDER BY tblPasswords.service
            """.format("'%" + search + "%'"), [user])

            data = cursor.fetchall()

            passwords = []
            for entry in data:
                password = security.decrypt(entry[3], security.password_hashed_once(user_password))
                passwords.append([entry[0], entry[1], entry[2], password])

            return passwords
    else:
        with sql.connect(FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT tblPasswords.ID, tblPasswords.service, tblPasswords.username, tblPasswords.password
            FROM tblPasswords
            WHERE tblPasswords.user = ?
            ORDER BY tblPasswords.service
            """, [user])

            data = cursor.fetchall()

            passwords = []
            for entry in data:
                password = security.decrypt(entry[3], security.password_hashed_once(user_password))
                passwords.append([entry[0], entry[1], entry[2], password])

            return passwords


def add_password(user, user_password, service, username, password):
    if not user_exists(user): return False

    with sql.connect(FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ID
            FROM tblPasswords
            ORDER BY ID DESC LIMIT 1""")
        data = cursor.fetchall()
        if not data:
            password_id = 1
        else:
            password_id = int(data[0][0]) + 1

    password_id = str(password_id).zfill(4)

    with sql.connect(FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO tblPasswords
            VALUES (?,?,?,?,?)
            """, (password_id, user, service, username,
                  security.encrypt(password, security.password_hashed_once(user_password))))

    return True


def remove_password(password_id):
    if not password_exists(password_id): return False

    with sql.connect(FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            DELETE FROM tblPasswords
            WHERE ID = ?
            """, [password_id])

    return True
