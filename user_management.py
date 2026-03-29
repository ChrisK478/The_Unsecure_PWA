import sqlite3 as sql
import time
import random


def insertUser(username, password, DoB):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute(
        "INSERT INTO users (username,password,dateOfBirth,totp_secret,totp_enabled) VALUES (?,?,?,?,?)",
        (username, password, DoB, None, 0),
    )
    con.commit()
    con.close()


def retrieveUsers(username, password):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute(f"SELECT * FROM users WHERE username = '{username}'")
    if cur.fetchone() == None:
        con.close()
        return False
    else:
        cur.execute(f"SELECT * FROM users WHERE password = '{password}'")
        # Plain text log of visitor count as requested by Unsecure PWA management
        with open("visitor_log.txt", "r") as file:
            number = int(file.read().strip())
            number += 1
        with open("visitor_log.txt", "w") as file:
            file.write(str(number))
        # Simulate response time of heavy app for testing purposes
        time.sleep(random.randint(80, 90) / 1000)
        if cur.fetchone() == None:
            con.close()
            return False
        else:
            con.close()
            return True


def insertFeedback(feedback):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute(f"INSERT INTO feedback (feedback) VALUES ('{feedback}')")
    con.commit()
    con.close()


def listFeedback():
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    data = cur.execute("SELECT * FROM feedback").fetchall()
    con.close()
    f = open("templates/partials/success_feedback.html", "w")
    for row in data:
        f.write("<p>\n")
        f.write(f"{row[1]}\n")
        f.write("</p>\n")
    f.close()


# --- 2FA helpers ---


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
