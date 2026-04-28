# vault.py

from encryption_util import encrypt, decrypt
from database import get_db_connection
import traceback

def add_credential(website, username, password):
    """Encrypt and store a new credential"""
    encrypted_password = encrypt(password)
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO credentials (website, username, password)
            VALUES (%s, %s, %s)
        """, (website, username, encrypted_password))
        conn.commit()
    except Exception as e:
        print(f"❌ Error adding credential: {e}")
    finally:
        cursor.close()
        conn.close()


def get_credentials():
    """Retrieve and decrypt all credentials"""
    conn = get_db_connection()
    cursor = conn.cursor()
    credentials = []
    try:
        cursor.execute("SELECT website, username, password FROM credentials")
        rows = cursor.fetchall()

        for website, username, encrypted_password in rows:
            try:
                decrypted_password = decrypt(encrypted_password)
                credentials.append({
                    'website': website,
                    'username': username,
                    'password': decrypted_password
                })
            except Exception as e:
                print(f"⚠️ Decryption failed for {website} ({username}): {e}")
                continue
    except Exception as e:
        print(f"❌ Error fetching credentials: {e}")
    finally:
        cursor.close()
        conn.close()

    return credentials


def delete_credential(website, username):
    """Delete a credential using website + username as identifier"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "DELETE FROM credentials WHERE website = %s AND username = %s",
            (website, username)
        )
        conn.commit()
        affected = cursor.rowcount
    except Exception as e:
        print(f"❌ Error deleting credential: {e}")
        affected = 0
    finally:
        cursor.close()
        conn.close()

    return affected > 0
