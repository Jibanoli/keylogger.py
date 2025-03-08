import tkinter as tk
from tkinter import messagebox
from pynput import keyboard
import json
import os
import threading
from PIL import ImageGrab
import hashlib

# Database File
USER_DB_FILE = "users.json"
KEYLOG_FILE = "keystrokes.txt"
logging_active = False

# Salt for Password Hashing (optional, but recommended)
SALT = "some_random_salt_here"

# Load User Data
def load_users():
    if os.path.exists(USER_DB_FILE):
        with open(USER_DB_FILE, "r") as f:
            return json.load(f)
    return {}

# Save User Data
def save_users(users):
    with open(USER_DB_FILE, "w") as f:
        json.dump(users, f)

# Hash password using SHA256 + Salt
def hash_password(password):
    return hashlib.sha256((password + SALT).encode()).hexdigest()

# Keystroke Logging Function
def log_key(key):
    with open(KEYLOG_FILE, "a") as f:
        try:
            f.write(f"{key.char}")
        except AttributeError:
            f.write(f" [{key}] ")

# Start Keylogger
def start_logging():
    global logging_active
    logging_active = True
    listener = keyboard.Listener(on_press=log_key)
    listener.start()

# Stop Keylogger
def stop_logging():
    global logging_active
    logging_active = False

# Take Screenshot
def take_screenshot():
    screenshot = ImageGrab.grab()
    screenshot.save("screenshot.png")
    messagebox.showinfo("Screenshot", "Screenshot saved as screenshot.png")

# Login Page
class LoginPage:
    def __init__(self, root):
        self.root = root
        self.root.title("Login - Keystroke Logger")
        self.root.geometry("400x400")
        self.root.configure(bg="#2c3e50")

        tk.Label(root, text="Keystroke Logger", font=("Arial", 24, "bold"), fg="white", bg="#2c3e50").pack(pady=20)
        tk.Label(root, text="Username:", fg="white", bg="#2c3e50").pack()
        self.username_entry = tk.Entry(root, width=30)
        self.username_entry.pack(pady=5)

        tk.Label(root, text="Password:", fg="white", bg="#2c3e50").pack()
        self.password_entry = tk.Entry(root, show="*", width=30)
        self.password_entry.pack(pady=5)

        tk.Button(root, text="Login", command=self.authenticate, bg="#27ae60", fg="white", width=20).pack(pady=10)
        tk.Button(root, text="Signup", command=self.open_signup, bg="#2980b9", fg="white", width=20).pack(pady=5)
        tk.Button(root, text="Forgot Password?", command=self.open_forgot_password, bg="#f1c40f", fg="black", width=20).pack(pady=5)

    def authenticate(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        users = load_users()

        # Hash the entered password before checking
        hashed_password = hash_password(password)

        if username in users and users[username]["password"] == hashed_password:
            messagebox.showinfo("Success", "Login Successful!")
            self.root.destroy()
            open_logger_interface()
        else:
            messagebox.showerror("Error", "Invalid Credentials")

    def open_signup(self):
        self.root.destroy()
        signup_root = tk.Tk()
        SignupPage(signup_root)
        signup_root.mainloop()

    def open_forgot_password(self):
        self.root.destroy()
        forgot_root = tk.Tk()
        ForgotPasswordPage(forgot_root)
        forgot_root.mainloop()

# Signup Page
class SignupPage:
    def __init__(self, root):
        self.root = root
        self.root.title("Signup - Keystroke Logger")
        self.root.geometry("400x500")
        self.root.configure(bg="#2c3e50")

        tk.Label(root, text="Create Account", font=("Arial", 20, "bold"), fg="white", bg="#2c3e50").pack(pady=20)

        tk.Label(root, text="First Name:", fg="white", bg="#2c3e50").pack()
        self.first_name_entry = tk.Entry(root, width=30)
        self.first_name_entry.pack(pady=5)

        tk.Label(root, text="Last Name:", fg="white", bg="#2c3e50").pack()
        self.last_name_entry = tk.Entry(root, width=30)
        self.last_name_entry.pack(pady=5)

        tk.Label(root, text="Username:", fg="white", bg="#2c3e50").pack()
        self.username_entry = tk.Entry(root, width=30)
        self.username_entry.pack(pady=5)

        tk.Label(root, text="Password:", fg="white", bg="#2c3e50").pack()
        self.password_entry = tk.Entry(root, show="*", width=30)
        self.password_entry.pack(pady=5)

        tk.Label(root, text="Confirm Password:", fg="white", bg="#2c3e50").pack()
        self.confirm_password_entry = tk.Entry(root, show="*", width=30)
        self.confirm_password_entry.pack(pady=5)

        tk.Button(root, text="Signup", command=self.signup, bg="#27ae60", fg="white", width=20).pack(pady=10)

    def signup(self):
        first_name = self.first_name_entry.get()
        last_name = self.last_name_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        # Check if passwords match
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return

        users = load_users()

        if username in users:
            messagebox.showerror("Error", "Username already exists!")
        else:
            # Hash the password before saving
            hashed_password = hash_password(password)
            users[username] = {
                "first_name": first_name,
                "last_name": last_name,
                "password": hashed_password
            }
            save_users(users)
            messagebox.showinfo("Success", "Signup successful! Please login.")
            self.root.destroy()
            open_login()

# Forgot Password Page
class ForgotPasswordPage:
    def __init__(self, root):
        self.root = root
        self.root.title("Forgot Password - Keystroke Logger")
        self.root.geometry("400x300")
        self.root.configure(bg="#2c3e50")

        tk.Label(root, text="Recover Password", font=("Arial", 20, "bold"), fg="white", bg="#2c3e50").pack(pady=20)
        tk.Label(root, text="Enter Username:", fg="white", bg="#2c3e50").pack()
        self.username_entry = tk.Entry(root, width=30)
        self.username_entry.pack(pady=5)

        tk.Button(root, text="Recover Password", command=self.recover_password, bg="#f1c40f", fg="black", width=20).pack(pady=10)

    def recover_password(self):
        username = self.username_entry.get()
        users = load_users()

        if username in users:
            password = users[username]["password"]
            messagebox.showinfo("Password Recovered", f"Your password: {password}")
            self.root.destroy()
            open_login()
        else:
            messagebox.showerror("Error", "Username not found!")

# Keystroke Logger Interface
class KeyloggerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Keystroke Logger")
        self.root.geometry("500x400")
        self.root.configure(bg="#34495e")

        tk.Label(root, text="Keystroke Logger", font=("Arial", 20, "bold"), fg="white", bg="#34495e").pack(pady=20)

        self.status_label = tk.Label(root, text="Click Start to begin logging", font=("Arial", 12), fg="white", bg="#34495e")
        self.status_label.pack(pady=10)

        self.start_button = tk.Button(root, text="Start Logging", command=self.start_logging, bg="#27ae60", fg="white", width=20)
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(root, text="Stop Logging", command=self.stop_logging, bg="#e74c3c", fg="white", width=20)
        self.stop_button.pack(pady=5)

        self.screenshot_button = tk.Button(root, text="Take Screenshot", command=take_screenshot, bg="#f1c40f", fg="black", width=20)
        self.screenshot_button.pack(pady=5)

        self.view_button = tk.Button(root, text="View Logs", command=self.view_logs, bg="#2980b9", fg="white", width=20)
        self.view_button.pack(pady=5)

        self.log_display = tk.Text(root, height=10, width=60)
        self.log_display.pack(pady=10)

    def start_logging(self):
        self.status_label.config(text="Logging started...")
        threading.Thread(target=start_logging, daemon=True).start()

    def stop_logging(self):
        self.status_label.config(text="Logging stopped")
        stop_logging()

    def view_logs(self):
        if os.path.exists(KEYLOG_FILE) and os.path.getsize(KEYLOG_FILE) > 0:
            with open(KEYLOG_FILE, "r") as f:
                self.log_display.delete("1.0", tk.END)
                self.log_display.insert(tk.END, f.read())
        else:
            messagebox.showinfo("Info", "No logs found or file is empty.")

# Function to Open Login Page
def open_login():
    login_root = tk.Tk()
    LoginPage(login_root)
    login_root.mainloop()

# Function to Open Logger Interface
def open_logger_interface():
    logger_root = tk.Tk()
    KeyloggerApp(logger_root)
    logger_root.mainloop()

# Start with the Login Page
open_login()
