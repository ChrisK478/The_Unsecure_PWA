import sqlite3 as sql
import time
import random
import bcrypt


def insertUser(username, password, DoB):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    hashed_str = hashed.decode("utf-8")

    cur.execute(
        "INSERT INTO users (username, password, dateOfBirth, totp_secret, totp_enabled) VALUES (?,?,?,?,?)",
        (username, hashed_str, DoB, None, 0),
    )
    con.commit()
    con.close()


def retrieveUsers(username, password):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()

    cur.execute("SELECT password FROM users WHERE username = ?", (username,))
    row = cur.fetchone()

    with open("visitor_log.txt", "r") as file:
        number = int(file.read().strip())
        number += 1
    with open("visitor_log.txt", "w") as file:
        file.write(str(number))

    time.sleep(random.randint(80, 90) / 1000)

    if row is None:
        con.close()
        return False

    stored = row[0]

    # bcrypt hashes start with $2a$, $2b$, or $2y$
    if isinstance(stored, str) and stored.startswith(("$2a$", "$2b$", "$2y$")):
        ok = bcrypt.checkpw(password.encode("utf-8"), stored.encode("utf-8"))
        con.close()
        return ok

    # legacy plaintext fallback (one-time migration)
    if stored == password:
        new_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode(
            "utf-8"
        )
        cur.execute(
            "UPDATE users SET password = ? WHERE username = ?", (new_hash, username)
        )
        con.commit()
        con.close()
        return True

    con.close()
    return False


def insertFeedback(feedback):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("INSERT INTO feedback (feedback) VALUES (?)", (feedback,))
    con.commit()
    con.close()


def listFeedback():
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    data = cur.execute("SELECT feedback FROM feedback").fetchall()
    con.close()
    return [row[0] for row in data]


# 2FA


def get_totp_secret(username):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("SELECT totp_secret FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    con.close()
    return row[0] if row else None


def set_totp_secret(username, secret):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute(
        "UPDATE users SET totp_secret = ? WHERE username = ?", (secret, username)
    )
    con.commit()
    con.close()


def is_totp_enabled(username):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("SELECT totp_enabled FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    con.close()
    return row and row[0] == 1


def enable_totp(username):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("UPDATE users SET totp_enabled = 1 WHERE username = ?", (username,))
    con.commit()
    con.close()
