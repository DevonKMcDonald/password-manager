import tkinter as tk
from tkinter import messagebox
import pyperclip
from cryptography.fernet import Fernet

class PasswordManager:
    def __init__(self):
        self.key = self.generate_key()
        self.passwords = {}

    def generate_key(self):
        return Fernet.generate_key()

    def encrypt_password(self, password):
        f = Fernet(self.key)
        return f.encrypt(password.encode()).decode()

    def decrypt_password(self, encrypted_password):
        f = Fernet(self.key)
        return f.decrypt(encrypted_password.encode()).decode()

    def add_password(self, service, username, password):
        encrypted_password = self.encrypt_password(password)
        self.passwords[service] = {'username': username, 'password': encrypted_password}

    def get_password(self, service):
        if service in self.passwords:
            encrypted_password = self.passwords[service]['password']
            decrypted_password = self.decrypt_password(encrypted_password)
            return self.passwords[service]['username'], decrypted_password
        else:
            return None

class PasswordManagerApp:
    def __init__(self):
        self.password_manager = PasswordManager()
        self.setup_gui()

    def setup_gui(self):
        self.window = tk.Tk()
        self.window.title("Password Manager")
        self.window.configure(bg="#F0F0F0")

        center_frame = tk.Frame(self.window, bg="#F0F0F0")
        center_frame.pack(padx=20, pady=20)

        instruction_label = tk.Label(center_frame, text=self.get_instructions(), bg="#F0F0F0", font=("Helvetica", 12))
        instruction_label.grid(row=0, column=0, columnspan=2, padx=10, pady=5)

        service_label = tk.Label(center_frame, text="Account:", bg="#F0F0F0", font=("Helvetica", 10))
        service_label.grid(row=1, column=0, padx=10, pady=5, sticky="e")
        self.service_entry = tk.Entry(center_frame, font=("Helvetica", 10))
        self.service_entry.grid(row=1, column=1, padx=10, pady=5)

        username_label = tk.Label(center_frame, text="Username:", bg="#F0F0F0", font=("Helvetica", 10))
        username_label.grid(row=2, column=0, padx=10, pady=5, sticky="e")
        self.username_entry = tk.Entry(center_frame, font=("Helvetica", 10))
        self.username_entry.grid(row=2, column=1, padx=10, pady=5)

        password_label = tk.Label(center_frame, text="Password:", bg="#F0F0F0", font=("Helvetica", 10))
        password_label.grid(row=3, column=0, padx=10, pady=5, sticky="e")
        self.password_entry = tk.Entry(center_frame, show="*", font=("Helvetica", 10))
        self.password_entry.grid(row=3, column=1, padx=10, pady=5)

        add_button = tk.Button(center_frame, text="Add Password", command=self.add_password, font=("Helvetica", 10), bg="#4CAF50", fg="white", relief="flat")
        add_button.grid(row=5, column=0, padx=10, pady=5, columnspan=2, sticky="we")

        get_button = tk.Button(center_frame, text="Get Password", command=self.get_password, font=("Helvetica", 10), bg="#008CBA", fg="white", relief="flat")
        get_button.grid(row=6, column=0, padx=10, pady=5, columnspan=2, sticky="we")

        signature_label = tk.Label(center_frame, text=self.get_signature(), bg="#F0F0F0", font=("Helvetica", 8))
        signature_label.grid(row=7, column=0, columnspan=2, padx=10, pady=5)

        self.window.mainloop()

    def get_instructions(self):
        return '''To add password, fill in all the fields and press "Add Password".
To view password, enter the account name and press "Get Password".'''

    def get_signature(self):
        return "Developed by Devon K McDonald"

    def add_password(self):
        service = self.service_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()

        if service and username and password:
            self.password_manager.add_password(service, username, password)
            messagebox.showinfo("Success", "Password added successfully!")
        else:
            messagebox.showwarning("Error", "Please fill in all the fields.")

    def get_password(self):
        service = self.service_entry.get()
        result = self.password_manager.get_password(service)
        if result:
            username, decrypted_password = result
            pyperclip.copy(decrypted_password)  # Copy password to clipboard
            messagebox.showinfo("Password", f"Username: {username}\nPassword: {decrypted_password}\nPassword copied to clipboard.")
        else:
            messagebox.showwarning("Error", "Password not found.")

if __name__ == "__main__":
    app = PasswordManagerApp()
