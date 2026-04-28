# database.py

import mysql.connector
import os
import bcrypt
from cryptography.fernet import Fernet

# Load DB credentials from environment variables (set them before running)
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "root")
DB_PASS = os.getenv("DB_PASS", "Rathore@2106")
DB_NAME = os.getenv("DB_NAME", "password_vault")

# Generate or load encryption key (keep this file safe!)
KEY_FILE = "secret.key"

def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return key

fernet = Fernet(load_key())

def get_db_connection():
    conn = mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME
    )
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Store credentials encrypted
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INT AUTO_INCREMENT PRIMARY KEY,
            website VARCHAR(255) NOT NULL,
            username VARCHAR(255) NOT NULL,
            password BLOB NOT NULL
        )
    ''')

    # Store only hashed master password
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS master (
            id INT AUTO_INCREMENT PRIMARY KEY,
            password_hash VARBINARY(255) NOT NULL
        )
    ''')

    conn.commit()
    cursor.close()
    conn.close()

def store_master_password(plain_password: str):
    conn = get_db_connection()
    cursor = conn.cursor()

    hashed = bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt())
    cursor.execute("INSERT INTO master (password_hash) VALUES (%s)", (hashed,))
    conn.commit()
    cursor.close()
    conn.close()

def verify_master_password(plain_password: str) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM master LIMIT 1")
    row = cursor.fetchone()
    cursor.close()
    conn.close()

    if row:
        return bcrypt.checkpw(plain_password.encode(), row[0].encode() if isinstance(row[0], str) else row[0])
    return False

def store_credential(website: str, username: str, plain_password: str):
    encrypted = fernet.encrypt(plain_password.encode())
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO credentials (website, username, password) VALUES (%s, %s, %s)",
        (website, username, encrypted)
    )
    conn.commit()
    cursor.close()
    conn.close()

def get_credentials():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT website, username, password FROM credentials")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    # Decrypt passwords
    return [(site, user, fernet.decrypt(pw).decode()) for site, user, pw in rows]
