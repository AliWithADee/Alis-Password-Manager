import sqlite3 as sql

from security import password_hashed_once, password_hashed_twice, encrypt, decrypt

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


def add_user(username, password):
    if user_exists(username): return False

    with sql.connect(FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO tblUsers
        VALUES (?,?)
        """, (username, password_hashed_twice(password)))

    return True


def validate_password(username, password):
    with sql.connect(FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        SELECT password
        FROM tblUsers
        WHERE username = ?
        """, [username])

        data = cursor.fetchall()
        if password_hashed_twice(password) == data[0][0]:
            return True

    return False


def get_passwords(user, user_pass, search=None):
    if search:
        with sql.connect(FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT tblPasswords.ID, tblPasswords.service, tblPasswords.username, tblPasswords.password
            FROM tblPasswords
            WHERE tblPasswords.user = ? AND tblPasswords.service LIKE {}
            """.format("'%" + search + "%'"), [user])

            data = cursor.fetchall()

            passwords = []
            for entry in data:
                password = decrypt(entry[3], password_hashed_once(user_pass))
                passwords.append([entry[0], entry[1], entry[2], password])

            return passwords
    else:
        with sql.connect(FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT tblPasswords.ID, tblPasswords.service, tblPasswords.username, tblPasswords.password
            FROM tblPasswords
            WHERE tblPasswords.user = ?
            """, [user])

            data = cursor.fetchall()

            passwords = []
            for entry in data:
                password = decrypt(entry[3], password_hashed_once(user_pass))
                passwords.append([entry[0], entry[1], entry[2], password])

            return passwords


def add_password(user, user_pass, service, username, password):
    if not user_exists(user): return False

    with sql.connect(FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ID
            FROM tblPasswords
            ORDER BY ID DESC LIMIT 1""")
        data = cursor.fetchall()
        if not data:
            new_id = 1
        else:
            new_id = int(data[0][0]) + 1

    new_id = str(new_id).zfill(4)

    with sql.connect(FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO tblPasswords
            VALUES (?,?,?,?,?)
            """, (new_id, user, service, username, encrypt(password, password_hashed_once(user_pass))))

    return True


def delete_password(password_id):
    if not password_exists(password_id): return False

    with sql.connect(FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            DELETE FROM tblPasswords
            WHERE ID = ?
            """, [password_id])

    return True
