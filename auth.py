import bcrypt
from database import init_db, get_db_connection

# Initialize DB tables (optional, better to run in main.py)
init_db()

def hash_password(password):
    """Hash the master password securely using bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def is_first_time():
    """Check if master password is set."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM master")
    result = cursor.fetchone()[0]
    conn.close()
    return result == 0

def set_master_password(password):
    """Store hashed master password."""
    hashed = hash_password(password)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO master (password) VALUES (%s)", (hashed,))
    conn.commit()
    conn.close()

def verify_master_password(password):
    """Verify input password against stored hash."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM master LIMIT 1")
    result = cursor.fetchone()
    conn.close()
    if result:
        stored_hash = result[0]
        return bcrypt.checkpw(password.encode(), stored_hash.encode())
    return False
