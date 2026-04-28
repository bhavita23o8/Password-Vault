import tkinter as tk
from tkinter import messagebox
from vault import add_credential, get_credentials, delete_credential
from breach_checker import check_password_breach, check_email_breach
from auth import verify_master_password  # to re-authenticate
from tkinter import ttk
import traceback
from tkinter import simpledialog
import time
from phishing_checker import is_phishing_url
import string
import random
import os
api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")



def open_vault_window():

    vault_window = tk.Tk()
    INACTIVITY_TIMEOUT = 5 * 60 * 1000  # 5 minutes in milliseconds
    last_activity = [time.time()]  # use a mutable object so inner function can update

    def reset_timer(event=None):
        last_activity[0] = time.time()
        vault_window.after_cancel(inactivity_check)  # cancel previous timer
        schedule_inactivity_check()

    def lock_and_reauthenticate():
        vault_window.withdraw()
        master_pwd = simpledialog.askstring("Session Locked", "Re-enter your master password:", show="*")
        if master_pwd and verify_master_password(master_pwd):
            vault_window.deiconify()
            reset_timer()
        else:
            messagebox.showwarning("Access Denied", "Incorrect password. Closing vault.")
            vault_window.destroy()

    def schedule_inactivity_check():
        global inactivity_check
        inactivity_check = vault_window.after(INACTIVITY_TIMEOUT, lock_and_reauthenticate)

    # Bind activity
    vault_window.bind_all("<Any-KeyPress>", reset_timer)
    vault_window.bind_all("<Any-Button>", reset_timer)

    schedule_inactivity_check()

    vault_window.title("Password Vault")
    vault_window.geometry("520x450")
    vault_window.configure(bg="#f0f0f0")  # light neutral background

    style = ttk.Style()
    style.theme_use('clam')

    # Simple, neutral style for ttk widgets
    style.configure("TButton",
                    font=("Segoe UI", 10),
                    padding=6,
                    background="#e1e1e1",
                    foreground="black")
    style.map("TButton",
              background=[("active", "#d4d4d4")])

    style.configure("TLabel",
                    background="#f0f0f0",
                    foreground="black",
                    font=("Segoe UI", 11))

    style.configure("TEntry",
                    padding=4,
                    font=("Segoe UI", 10))

    frame = ttk.Frame(vault_window, padding=15, style="TFrame")
    frame.grid(row=0, column=0, sticky="nsew")

    ttk.Label(frame, text="Website:").grid(row=0, column=0, sticky="w", pady=8)
    website_entry = ttk.Entry(frame, width=35)
    website_entry.grid(row=0, column=1, pady=8)

    ttk.Label(frame, text="Username:").grid(row=1, column=0, sticky="w", pady=8)
    username_entry = ttk.Entry(frame, width=35)
    username_entry.grid(row=1, column=1, pady=8)

    ttk.Label(frame, text="Password:").grid(row=2, column=0, sticky="w", pady=8)
    password_entry = ttk.Entry(frame, width=35, show="*")
    password_entry.grid(row=2, column=1, pady=8)
    password_strength_label = ttk.Label(frame, text="Strength: ", foreground="gray")
    password_strength_label.grid(row=2, column=4, padx=5, sticky="w")


    def generate_password(length=12):
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choices(chars, k=length))

    def check_password_strength(password):
        strength = "Weak ⚠️"
        if len(password) >= 8:
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_symbol = any(c in string.punctuation for c in password)
            score = sum([has_upper, has_lower, has_digit, has_symbol])
            if score >= 3:
                strength = "Medium ✅"
            if score == 4 and len(password) >= 12:
                strength = "Strong 🔒"
        return strength
    def update_strength_label(event=None):
        pwd = password_entry.get()
        strength = check_password_strength(pwd)
        
        # Set text and color based on strength
        if "Weak" in strength:
            password_strength_label.config(text=f"Strength: {strength}", foreground="red")
        elif "Medium" in strength:
            password_strength_label.config(text=f"Strength: {strength}", foreground="orange")
        else:
            password_strength_label.config(text=f"Strength: {strength}", foreground="green")


    password_entry.bind("<KeyRelease>", update_strength_label)

    def toggle_password():
        if password_entry.cget('show') == '':
            password_entry.config(show='*')
            toggle_btn.config(text="Show")
        else:
            password_entry.config(show='')
            toggle_btn.config(text="Hide")
    def insert_generated_password():
        pwd = generate_password()
        password_entry.delete(0, tk.END)
        password_entry.insert(0, pwd)
        update_strength_label(None)

    generate_btn = ttk.Button(frame, text="Generate", width=8, command=insert_generated_password)
    generate_btn.grid(row=2, column=3, padx=5)


    toggle_btn = ttk.Button(frame, text="Show", width=6, command=toggle_password)
    toggle_btn.grid(row=2, column=2, padx=5, pady=8)
    search_frame = ttk.Frame(frame)
    search_frame.grid(row=3, column=0, columnspan=3, pady=10, sticky="ew")

    search_entry = ttk.Entry(search_frame, width=35)
    search_entry.grid(row=0, column=0, padx=(0, 10))

    def search_credentials():
        query = search_entry.get().lower()
        listbox.delete(0, tk.END)
        try:
            credentials = get_credentials()
            for cred in credentials:
                combined = f"{cred['website']} | {cred['username']} | {cred['password']}"
                if query in combined.lower():
                    listbox.insert(tk.END, combined)
        except Exception as e:
            traceback.print_exc()
            messagebox.showerror("Error", f"Failed to search credentials.\n{e}")

    ttk.Button(search_frame, text="Search", command=search_credentials).grid(row=0, column=1)

    def clear_search():
        search_entry.delete(0, tk.END)
        refresh_listbox()

    ttk.Button(search_frame, text="Clear", command=clear_search).grid(row=0, column=2, padx=(10, 0))


    list_frame = ttk.Frame(frame)
    list_frame.grid(row=4, column=0, columnspan=3, pady=15)

    scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL)
    listbox = tk.Listbox(list_frame, width=60, height=10, yscrollcommand=scrollbar.set,
                         bg="white", fg="black", font=("Segoe UI", 10), selectbackground="#cce6ff")
    scrollbar.config(command=listbox.yview)
    listbox.grid(row=0, column=0)
    scrollbar.grid(row=0, column=1, sticky="ns")

    def refresh_listbox():
        listbox.delete(0, tk.END)
        try:
            credentials = get_credentials()
            for cred in credentials:
                listbox.insert(tk.END, f"{cred['website']} | {cred['username']} | {cred['password']}")
        except Exception as e:
            traceback.print_exc()
            messagebox.showerror("Error", f"Failed to decrypt credentials.\n{e}")
    
    def add_entry():
        website = website_entry.get()
        username = username_entry.get()
        password = password_entry.get()

        if website and username and password:
            # 🔹 Step 1: Phishing URL check
            if is_phishing_url(website, api_key):
                proceed = messagebox.askyesno(
                    "⚠️ Phishing Alert",
                    "This website might be malicious or phishing.\nDo you still want to add it?"
                )
                if not proceed:
                    return

            # 🔹 Step 2: Breach check for password
            breach_count = check_password_breach(password)
            if breach_count > 0:
                proceed = messagebox.askyesno(
                    "⚠️ Breached Password",
                    f"This password has appeared {breach_count} times in data breaches!\n"
                    "It is unsafe to use.\nDo you still want to save it?"
                )
                if not proceed:
                    return

            # 🔹 Step 3: Breach check for email/username (only if it looks like an email)
            if "@" in username and "." in username:
                breaches = check_email_breach(username, HIBP_API_KEY)
                if breaches:
                    proceed = messagebox.askyesno(
                        "⚠️ Breached Email",
                        f"This email/username was found in breaches: {', '.join(breaches)}\n"
                        "It might be unsafe to use.\nDo you still want to save it?"
                    )
                    if not proceed:
                        return

            # 🔹 Step 4: Save to DB
            add_credential(website, username, password)
            refresh_listbox()
            website_entry.delete(0, tk.END)
            username_entry.delete(0, tk.END)
            password_entry.delete(0, tk.END)
        else:
            messagebox.showwarning("Input Error", "Please fill all fields.")

    
    def delete_selected():
        selected = listbox.curselection()
        if selected:
            item = listbox.get(selected[0])
            website = item.split('|')[0].strip()
            if delete_credential(website):
                refresh_listbox()
            else:
                messagebox.showinfo("Not Found", "Credential not found.")
        else:
            messagebox.showwarning("No Selection", "Please select an entry to delete.")

    btn_frame = ttk.Frame(frame)
    btn_frame.grid(row=5, column=0, columnspan=3, pady=10)

    ttk.Button(btn_frame, text="Add", width=15, command=add_entry).grid(row=0, column=0, padx=10)
    ttk.Button(btn_frame, text="Delete Selected", width=15, command=delete_selected).grid(row=0, column=1, padx=10)
    ttk.Button(btn_frame, text="Close", width=15, command=vault_window.destroy).grid(row=0, column=2, padx=10)

    refresh_listbox()
    vault_window.mainloop()
