import tkinter as tk
from tkinter import ttk, messagebox
from collections import Counter
from PIL import Image, ImageTk
import os
from tinydb import TinyDB

import lib.hashing as hashe
import lib.generator as generator
import lib.dbms as dbms

master = "mypass123"
pass_db = TinyDB('passwords.json')

email_origin = "goof@yahoo.com" # the same as the below do what u want
master_pass = "mypass123" # set ur jason file and define it as master_pass
otp_origin = "123456"  # this for OTP idk what u will do for it

# Sample registry data
#brh
registry_data = {
    "Apps": {
        "Reddit": {"Kami": "password123"},
        "Instagram": {""}
    },
    "Websites": {
        "Google": {
            "Drive": {"": "password123"},
            "Chrome": {"": ""}
        },
        "Microsoft": {
            "OneDrive": {"": ""},
            "Outlook": {"": ""}
        }
    },
    "Games": {
        "CS2": "",
        "GTA5": ""
    }
}


class LoginWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("HexaVault - Login")
        self.geometry("400x270")

        script_dire = os.getcwd() + "/gui/"
        self.logo = ImageTk.PhotoImage(Image.open(os.path.join(script_dire, "logo_B.png")).resize((10, 10)))

        self.iconphoto(True, self.logo)

        # Load Azure theme
        self.load_azure_theme()


        tk.Label(self, text="Email:").pack(pady=14)
        self.email_entry = tk.Entry(self, width=40)
        self.email_entry.pack(pady=5)

        tk.Label(self, text="Master Password:").pack(pady=10)

        # Frame for password entry and eye icon
        password_frame = tk.Frame(self)
        password_frame.pack(pady=5)

        # Password entry (initially masked with *)
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(password_frame, textvariable=self.password_var, show="*", width=35)
        self.password_entry.grid(row=0, column=0)

        # Load the eye icon images
        script_dir = os.getcwd() + "/gui/"
        self.eye_open_image = ImageTk.PhotoImage(Image.open(os.path.join(script_dir, "View(1).png")).resize((20, 20)))
        self.eye_closed_image = ImageTk.PhotoImage(Image.open(os.path.join(script_dir, "Hide(1).png")).resize((20, 20)))
        self.copy_image = ImageTk.PhotoImage(Image.open(os.path.join(script_dir, "copy_0_W.png")).resize((20, 20)))

        self.show_password = False

        # Create the eye button (as a Label) and keep reference
        self.eye_button = tk.Label(password_frame, image = self.eye_closed_image, cursor="hand2")
        self.eye_button.grid(row=0, column=1, padx=5)
        self.eye_button.bind("<Button-1>", self.toggle_password)

        # Add Account button
        self.add_button = ttk.Button(self, text="Login", command=self.add_account)
        self.add_button.pack(pady=5)

    def toggle_password(self, event=None):
        """Toggle password visibility."""
        if self.show_password:
            self.password_entry.config(show="*")
            self.eye_button.config(image=self.eye_closed_image)
            self.show_password = False
        else:
            self.password_entry.config(show="")
            self.eye_button.config(image=self.eye_open_image)
            self.show_password = True

    def load_azure_theme(self):
        script_dir = os.getcwd() + "/gui/"
        theme_file = os.path.join(script_dir, "azure.tcl")
        if os.path.exists(theme_file):
            self.tk.call("source", theme_file)
            self.tk.call("set_theme", "dark")  # You can choose between "light" and "dark"
        else:
            print(f"Theme file {theme_file} not found. Using default theme.")

    def add_account(self):
        email = self.email_entry.get()
        masterp = self.password_entry.get()
        hashed_mp = hashe.hash_passwd(masterp)
        hashed_ml = hashe.hash_passwd(email)

        if not masterp or not email or not hashe.check_passwd(master, hashed_mp) or not hashe.check_passwd(email_origin, hashed_ml):
            messagebox.showwarning("Input Error", "password or Email is incorrect. Please try again.")
            return

        if hashe.check_passwd(master, hashed_mp) and hashe.check_passwd(email_origin, hashed_ml):
            print(f"master password = {masterp}, email = {email}")  # where "masterp" is the variable containing the master password you get from text box
            self.destroy()
            DualFA(self.copy_image)

class DualFA(tk.Tk):
    def __init__(self, copy_image, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title("Dual-Factor Authentication")
        self.geometry("400x200")
        self.copy_image = copy_image

        # Load Azure theme
        self.load_azure_theme()

        tk.Label(self, text="Enter the OTP").pack(pady=25)
        self.dual_fa_entry = tk.Entry(self, width=40)
        self.dual_fa_entry.pack(pady=5)

        self.add_button = ttk.Button(self, text="Login", command=self.check_otp)
        self.add_button.pack(pady=10)

    def load_azure_theme(self):
        script_dir = os.getcwd() + "/gui/"
        theme_file = os.path.join(script_dir, "azure.tcl")
        if os.path.exists(theme_file):
            self.tk.call("source", theme_file)
            self.tk.call("set_theme", "dark")  # You can choose between "light" and "dark"
        else:
            print(f"Theme file {theme_file} not found. Using default theme.")

    def check_otp(self):
        otp=self.dual_fa_entry.get()

        if not otp or otp != otp_origin:  # Compare with the predefined OTP
            messagebox.showwarning("Input Error", "OTP is incorrect. Please try again.")
            return

        if  otp == otp_origin:
            self.destroy()
            exit(0)
            #MainPage(self.copy_image)

def mainloop_tk():
    root = tk.Tk()  # Create the main application root
    root.withdraw()  # Hide the root window until login is done
    login_window = LoginWindow(root)  # Create login window

    login_window.protocol("WM_DELETE_WINDOW", root.quit)  # If login window is closed, quit the app
    login_window.mainloop()

mainloop_tk()