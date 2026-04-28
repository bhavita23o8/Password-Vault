# Password-Vault
A secure application designed to store and manage user credentials using strong encryption and authentication. It enhances cybersecurity by integrating password strength analysis, breach detection, and phishing protection to ensure safe password management.


# Key Features
🔒 1. Secure Credential Storage

Uses encryption techniques to securely store passwords, ensuring that sensitive data remains protected from unauthorized access.

🧠 2. Password Strength Analysis

Evaluates passwords using advanced methods to detect weak or predictable patterns and provides real-time suggestions for improvement.

⚠️ 3. Breach Detection

Checks whether a password has been exposed in known data breaches and alerts users to update compromised credentials.

🛡️ 4. Phishing Detection

Identifies suspicious or malicious URLs using pattern analysis and APIs, helping users avoid phishing attacks.

🖥️ 5. User-Friendly Interface

Developed using Tkinter, offering an easy-to-use interface for adding, viewing, searching, and managing stored credentials.

⏱️ 6. Session Security

Includes features like auto-lock after inactivity and master password authentication to enhance system security.


# Tech Stack
Backend: Python            
Security: Cryptography, bcrypt
Libraries: zxcvbn, requests
Frontend: Tkinter
Database: MySQL / Encrypted storage


# Setup & Run
pip install -r requirements.txt
python main.py
