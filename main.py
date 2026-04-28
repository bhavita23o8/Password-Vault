import tkinter as tk
from tkinter import simpledialog, messagebox
from vault_gui import open_vault_window
from database import init_db
from auth import is_first_time, set_master_password, verify_master_password
import time
import os

# Initialize DB
init_db()

MAX_ATTEMPTS = 2
LOCKOUT_DURATION = 60  # seconds
LOCK_FILE = "data/lockout.txt"  # store inside data folder


def is_locked_out():
    """Check if the user is currently locked out."""
    if os.path.exists(LOCK_FILE):
        with open(LOCK_FILE, 'r') as f:
            lock_time = float(f.read())
        if time.time() < lock_time + LOCKOUT_DURATION:
            return True, int(lock_time + LOCKOUT_DURATION - time.time())
        else:
            os.remove(LOCK_FILE)
    return False, 0


def ask_master_password(prompt="Enter your master password:"):
    """Ask user for master password using a secure Tkinter dialog."""
    root = tk.Tk()
    root.withdraw()
    pwd = simpledialog.askstring("Master Password", prompt, show='*')
    root.destroy()
    return pwd


def main():
    if is_first_time():
        pwd1 = ask_master_password("Create a master password:")
        pwd2 = ask_master_password("Confirm master password:")
        if not pwd1 or pwd1 != pwd2:
            messagebox.showerror("Error", "Passwords do not match or are empty. Exiting.")
            return
        set_master_password(pwd1)
        messagebox.showinfo("Success", "Master password set. Please login again.")
        return  # exit after setup

    # Check if locked
    locked, remaining = is_locked_out()
    if locked:
        messagebox.showwarning("Locked Out", f"Too many failed attempts. Try again after {remaining} seconds.")
        return

    # Attempt login
    attempts = 0
    while attempts < MAX_ATTEMPTS:
        master_pwd = ask_master_password()
        if master_pwd and verify_master_password(master_pwd):
            open_vault_window()  # Open GUI vault
            return
        else:
            attempts += 1
            if master_pwd is None:  # user cancelled
                return
            messagebox.showerror("Error", f"Incorrect master password ({attempts}/{MAX_ATTEMPTS}).")

    # Lock out
    os.makedirs(os.path.dirname(LOCK_FILE), exist_ok=True)
    with open(LOCK_FILE, 'w') as f:
        f.write(str(time.time()))
    messagebox.showwarning("Locked", f"Too many incorrect attempts. Locked for {LOCKOUT_DURATION} seconds.")


if __name__ == "__main__":
    main()
