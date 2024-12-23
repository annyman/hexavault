import tkinter as tk
from tkinter import ttk, messagebox
from collections import Counter
from PIL import Image, ImageTk
import os
from tinydb import TinyDB, where

import lib.hashing as hashe
import lib.generator as generator
import lib.encryption as enc
import lib.dbms as dbms
import lib.sync as sync
import lib.mailing as mailing

pass_db = TinyDB('passwords.json')

# Sample registry data
#brh
registry_data = TinyDB('passwords.json')

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
        self.search_icons = ImageTk.PhotoImage(Image.open(os.path.join(script_dir, "search_icon.png")).resize((20, 20)))

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

        global master_pass;
        global email_origin;
        master_pass, email_origin = masterp, email

        if not masterp or not email or not hashe.check_passwd(master_pass, hashed_mp) or not hashe.check_passwd(email_origin, hashed_ml):
            messagebox.showwarning("Input Error", "password or Email is incorrect. Please try again.")
            return

        if hashe.check_passwd(master_pass, hashed_mp) and hashe.check_passwd(email_origin, hashed_ml):
            print(f"master password = {masterp}, email = {email}")  # where "masterp" is the variable containing the master password you get from text box
            self.destroy()
            otp_origin = mailing.send_2fa(email_origin)
            DualFA(self.copy_image, self.search_icons, otp_origin)

class DualFA(tk.Tk):
    def __init__(self, copy_image, search_icons, otp, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title("Dual-Factor Authentication")
        self.geometry("400x200")
        self.copy_image = copy_image
        self.search_icons = search_icons
        self.otp = otp

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
        otp = self.dual_fa_entry.get()

        if not otp or otp != str(self.otp):  # Compare with the predefined OTP
            messagebox.showwarning("Input Error", "OTP is incorrect. Please try again.")
            return

        if  otp == str(self.otp):
            self.destroy()
            MainPage(self.copy_image, self.search_icons)


class MainPage(tk.Tk):
    def __init__(self, copy_image, search_icons, *args, **kwargs):  # Modified
        super().__init__(*args, **kwargs)
        self.title("HexaVault")
        self.geometry("500x360")
        self.copy_image = copy_image  # Store the copy_image in the class (Modified)
        self.search_icons = search_icons  # Store the search_icons in the class (Modified)

        self.load_azure_theme()

        script_dir = os.getcwd() + "/gui/"
        self.eye_open_image = ImageTk.PhotoImage(Image.open(os.path.join(script_dir, "View(1).png")).resize((20, 20)))
        self.eye_closed_image = ImageTk.PhotoImage(Image.open(os.path.join(script_dir, "Hide(1).png")).resize((20, 20)))
        self.search_icons = ImageTk.PhotoImage(Image.open(os.path.join(script_dir, "search_icon.png")).resize((20, 20)))

        # Dashboard frame to show password strength summary in a 2x2 grid with borders
        self.dashboard_frame = tk.Frame(self, bg="#2b2b2b", bd=2)
        self.dashboard_frame.pack(pady=7)

        # Titles for the grid elements
        title_font = ("Helvetica", 14, "bold")
        label_font = ("Helvetica", 12)

        # Create 2 rows and 2 columns for the dashboard
        self.repeated_passwords_label = tk.Label(self.dashboard_frame, text="Repeated Passwords",
                                                 borderwidth=2, relief="solid", width=20,
                                                 height=5, bg="#1c1c1c", fg="#ffffff", font=label_font)
        self.repeated_passwords_label.grid(row=0, column=0, padx=5, pady=5)

        self.weak_passwords_label = tk.Label(self.dashboard_frame, text="Weak Passwords",
                                             borderwidth=2, relief="solid", width=20,
                                             height=5, bg="#1c1c1c", fg="#ffffff", font=label_font)
        self.weak_passwords_label.grid(row=0, column=1, padx=5, pady=5)

        self.moderate_passwords_label = tk.Label(self.dashboard_frame, text="Moderate Passwords",
                                                 borderwidth=2, relief="solid", width=20,
                                                 height=5, bg="#1c1c1c", fg="#ffffff", font=label_font)
        self.moderate_passwords_label.grid(row=1, column=0, padx=5, pady=5)

        self.strong_passwords_label = tk.Label(self.dashboard_frame, text="Strong Passwords",
                                               borderwidth=2, relief="solid", width=20,
                                               height=5, bg="#1c1c1c", fg="#ffffff", font=label_font)
        self.strong_passwords_label.grid(row=1, column=1, padx=5, pady=5)

        # Display the initial dashboard
        self.update_dashboard()

        button_frame = tk.Frame(self)
        button_frame.pack(pady=12)

        # "Add a new Password" button
        self.add_password_button = ttk.Button(button_frame, text="Add a new Password", command=lambda: self.open_add_password_window(self.copy_image, self.search_icons), width=23)
        self.add_password_button.pack(side="left", padx=5)

        # "Passwords" button
        self.passwords_button = ttk.Button(button_frame, text="Passwords", command=lambda: self.open_pass(self.eye_open_image, self.eye_closed_image, self.copy_image, self.search_icons), width=23)
        self.passwords_button.pack(side="left", padx=5)

        # Center the button frame
        button_frame.pack(pady=7)

        # frame for import and export buttons
        button_framei = tk.Frame(self)
        button_framei.pack(pady=12)

        # "Import" button
        self.import_button = ttk.Button(button_framei, text="Import", command=self.import_passwords, width=23)
        self.import_button.pack(side="left", padx=5)

        # "Export" button
        self.export_button = ttk.Button(button_framei, text="Export", command=self.export_passwords, width=23)
        self.export_button.pack(side="left", padx=5)

        button_framei.pack(pady=7)


    def load_azure_theme(self):
        script_dir = os.getcwd() + "/gui/"
        theme_file = os.path.join(script_dir, "azure.tcl")
        if os.path.exists(theme_file):
            self.tk.call("source", theme_file)
            self.tk.call("set_theme", "dark")
        else:
            print(f"Theme file {theme_file} not found. Using default theme.")

    def update_dashboard(self):
        weak_count = 0
        moderate_count = 0
        strong_count = 0

        for app in registry_data:
            if app['strength'] == "WEAK":
                weak_count += 1
            elif app['strength'] == "MODERATE":
                moderate_count += 1
            elif app['strength'] == "STRONG":
                strong_count += 1

        # Update the dashboard labels with values
        self.repeated_passwords_label.config(text=f"Repeated Passwords\n0")
        self.weak_passwords_label.config(text=f"Weak Passwords\n{weak_count}")
        self.moderate_passwords_label.config(text=f"Moderate Passwords\n{moderate_count}")
        self.strong_passwords_label.config(text=f"Strong Passwords\n{strong_count}")

    def import_passwords(self):
        error = sync.import_encrypted_json('export.json', 'export.key', 'passwords.json', [master_pass + "\n", email_origin + "\n"])
        if not error:
            messagebox.showinfo("Success", "Imported successfully!")  # replace it later with actual import logic
        else:
            messagebox.showinfo("Failed", "Master password or email is not matching!")  # replace it later with actual import logic

    def export_passwords(self):
        sync.export_encrypted_json('passwords.json', 'export.json','export.key', [master_pass + "\n", email_origin + "\n"], email_origin)
        messagebox.showinfo("Success", "Exported successfully!")   # replace it later with actual export logic

    def open_add_password_window(self, copy_image, search_icons):
        AddPasswordWindow(self, copy_image, search_icons)          #opens AddPasswordWindow

    def open_pass(self, eye_open, eye_closed, copy_image, search_icons):
        HomePage(self, eye_open, eye_closed, copy_image, search_icons)              # opens HomePage

class AddPasswordWindow(tk.Toplevel):
    def __init__(self, parent, copy_image, search_icons):
        super().__init__()
        self.title("Add New Password")
        self.geometry("450x330")
        self.copy_image = copy_image
        self.search_icons = search_icons
        self.parent = parent
        self.use_nums = False
        self.use_chars = False
        self.use_spl = False
        self.should_gen = False
        self.attempts = False

        self.columnconfigure(0, weight=1)
        self.columnconfigure(5, weight=1)

        # Labels and entry fields for adding new password
        tk.Label(self, text="App/Website Name:").grid(row=0, column=1, padx=10, pady=5)
        self.name_entry = tk.Entry(self, width=35)
        self.name_entry.grid(row=1, column=1, padx=10, pady=5)

        tk.Label(self, text="Tags:").grid(row=2, column=1, padx=10, pady=5)
        self.tag_entry = tk.Entry(self, width=35)
        self.tag_entry.grid(row=3, column=1, padx=10, pady=5)

        tk.Label(self, text="Username:").grid(row=4, column=1, padx=10, pady=5)
        self.username_entry = tk.Entry(self, width=35)
        self.username_entry.grid(row=5, column=1, padx=10, pady=5)

        tk.Label(self, text="Password:").grid(row=6, column=1, padx=10, pady=5)
        password_frame = tk.Frame(self)
        password_frame.grid(row=7, column=1, padx=10, pady=5)

        # Password entry (initially masked with *)
        self.password_entry = tk.Entry(password_frame, show="*", width=30)
        self.password_entry.grid(row=0, column=0, padx=3)

        self.show_password = False

        script_dir = os.getcwd() + "/gui/"
        self.eye_open_image2 = ImageTk.PhotoImage(Image.open(os.path.join(script_dir, "View(1).png")).resize((20, 20)))
        self.eye_closed_image2 = ImageTk.PhotoImage(Image.open(os.path.join(script_dir, "Hide(1).png")).resize((20, 20)))

        # Create the eye button (as a Label) and keep reference
        self.eye_button = tk.Label(password_frame, image=self.eye_closed_image2, cursor="hand2")
        self.eye_button.grid(row=0, column=1, padx=3)
        self.eye_button.bind("<Button-1>", self.toggle_password)

        self.gen_pass = ttk.Button(self, text="Generate a Strong Password", command=self.open_generate_pass)
        self.gen_pass.grid(row=10, column=1, padx=10, pady=5)
        # Save button
        self.save_button = ttk.Button(self, text="Save", command=self.save_password)
        self.save_button.grid(row=10, column=2, padx=10, pady=15)

    def toggle_password(self, event=None):
        """Toggle password visibility."""
        if self.show_password:
            self.password_entry.config(show="*")
            self.eye_button.config(image=self.eye_closed_image2)
            self.show_password = False
        else:
            self.password_entry.config(show="")
            self.eye_button.config(image=self.eye_open_image2)
            self.show_password = True

    def open_generate_pass(self):
        Generate_Pass(self)

    def save_password(self):
        # Retrieve data from entries
        name = self.name_entry.get().strip()
        tag = self.tag_entry.get()
        username = self.username_entry.get().strip()
        if self.should_gen == True:
            password = generator.gen_random_passwd(16, self.use_chars, self.use_nums, self.use_spl)
        else:
            password = self.password_entry.get().strip()
        entry = dbms.ask_passwd(name, username, password, tag)
        # Validate inputs
        if not name or not username or not password:
            messagebox.showwarning("Input Error", "All fields must be filled!")
            return

        alert, strength, feedback = generator.check_strength(password)
        entry.strength = strength

        if self.attempts == True:
            messagebox.showinfo("Success", "Password added successfully!")
            dbms.add_passwd(registry_data, entry, master_pass)
            self.destroy() # Refresh the listbox in HomePage

        self.attempts = True

        if alert == True:
            messagebox.showwarning("Password Strength", strength + " password. Consider using a stronger password generated by our app")
            return
        # Notify user and close window
        else:
            messagebox.showinfo("Success", "Password added successfully!")
            dbms.add_passwd(registry_data, entry, master_pass)
            self.destroy() # Refresh the listbox in HomePage


class Generate_Pass(tk.Toplevel):  # Change tk.Tk to tk.Toplevel
    def __init__(self, parent):
        super().__init__(parent)  # Pass parent to the superclass
        self.parent = parent
        self.title("Password Generator")
        self.geometry("300x200")
        self.include_numbers = tk.BooleanVar()
        self.include_symbols = tk.BooleanVar()
        self.include_characters = tk.BooleanVar()
        self.create_widgets()

    def create_widgets(self):
        ttk.Label(self, text="Include in Password:").pack(pady=15)

        include_numbers_radio = ttk.Checkbutton(
            self,  # Use self instead of self.parent
            text="Numbers   ",
            variable=self.include_numbers,
            onvalue=True,
            offvalue=False
        )
        include_numbers_radio.pack()

        include_symbols_radio = ttk.Checkbutton(
            self,  # Use self instead of self.parent
            text="Symbols   ",
            variable=self.include_symbols,
            onvalue=True,
            offvalue=False
        )
        include_symbols_radio.pack()

        include_characters_radio = ttk.Checkbutton(
            self,  # Use self instead of self.parent
            text="Uppercase",
            variable=self.include_characters,
            onvalue=True,
            offvalue=False
        )
        include_characters_radio.pack()

        generate_button = ttk.Button(self, text="Generate Password", command=self.generate_password)
        generate_button.pack(pady=10)

    def generate_password(self):
        self.parent.use_nums = self.include_numbers.get()
        self.parent.use_spl = self.include_symbols.get()
        self.parent.use_chars = self.include_characters.get()

        self.parent.should_gen = True
        ######Add your password generation logic here currently just printing the selected options#####
        print(f"Numbers: {self.parent.use_nums}, Symbols: {self.parent.use_spl}, Characters: {self.parent.use_chars}")



class HomePage(tk.Toplevel):
    def __init__(self, parent, eye_open_image, eye_closed_image, copy_image, search_icons):
        super().__init__()
        self.title("HexaVault")
        self.geometry("600x400")
        self.parent = parent

        self.use_nums = False
        self.use_chars = False
        self.use_spl = False
        self.should_gen = False

        # Store images to prevent garbage collection
        self.eye_open_image = eye_open_image
        self.eye_closed_image = eye_closed_image
        self.copy_image = copy_image
        self.search_icons = search_icons

        # Left side: Search bar and listbox
        left_frame = tk.Frame(self)
        left_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        # Search bar with icon
        self.search_var = tk.StringVar()
        tk.Label(left_frame, text="Search Passwords:").pack()
        search_frame = tk.Frame(left_frame)
        search_frame.pack(pady=5)

        self.search_entry = tk.Entry(search_frame, textvariable=self.search_var, width=27)
        self.search_entry.pack(side="left", padx=(0, 5))

        search_button = tk.Label(search_frame, image=self.search_icons, cursor="hand2")
        search_button.pack(side="right")
        search_button.bind("<Button-1>", self.search_passwords)

        # Listbox to display apps/websites
        self.listbox = tk.Listbox(left_frame, width=30, height=15)
        self.listbox.pack(pady=10, fill="y")
        self.listbox.bind("<<ListboxSelect>>", self.on_select)

        # Right side: Details panel for viewing/editing entries
        self.details_panel = tk.Frame(self)
        self.details_panel.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        tk.Label(self.details_panel, text="Name of App/Website").pack(anchor="nw", padx=5, pady=5)
        self.name_entry = tk.Entry(self.details_panel)
        self.name_entry.pack(fill="x", padx=5, pady=5)

        tk.Label(self.details_panel, text="Tags").pack(anchor="nw", padx=5, pady=5)
        self.tag_entry = tk.Entry(self.details_panel)
        self.tag_entry.pack(fill="x", padx=5, pady=5)

        tk.Label(self.details_panel, text="Username").pack(anchor="nw", padx=5, pady=5)
        self.username_entry = tk.Entry(self.details_panel)
        self.username_entry.pack(fill="x", padx=5, pady=5)

        tk.Label(self.details_panel, text="Password").pack(anchor="nw", padx=5, pady=5)
        password_frame = tk.Frame(self.details_panel)
        password_frame.pack(fill="x", padx=5, pady=5)

        self.password_entry = tk.Entry(password_frame, show="*", width=30)
        self.password_entry.grid(row=0, column=0)

        self.show_password = False
        self.eye_button = tk.Label(password_frame, image=self.eye_closed_image, cursor="hand2")
        self.eye_button.grid(row=0, column=1, padx=5)
        self.eye_button.bind("<Button-1>", self.toggle_password)

        self.copy_button = tk.Label(password_frame, image=self.copy_image, cursor="hand2")
        self.copy_button.grid(row=0, column=2, padx=5)
        self.copy_button.bind("<Button-1>", self.copy_to_clipboard)

        self.gen_pass = ttk.Button(self.details_panel, text="Generate a Strong Password", command=self.open_generate_pass)
        self.gen_pass.pack(pady=15)

        # Save button
        self.save_button = ttk.Button(self.details_panel, text="Save", command=self.save_value)
        self.save_button.pack(pady=10)

        # Populate the listbox initially
        self.populate_listbox()

    def toggle_password(self, event=None):
        if self.show_password:
            self.password_entry.config(show="*")
            self.eye_button.config(image=self.eye_closed_image)
            self.show_password = False
        else:
            self.password_entry.config(show="")
            self.eye_button.config(image=self.eye_open_image)
            self.show_password = True

    def open_generate_pass(self):
        Generate_Pass(self)

    def copy_to_clipboard(self, event=None):
        self.clipboard_clear()
        self.clipboard_append(self.password_entry.get())
        messagebox.showinfo("Info", "Password copied to clipboard!")

    def populate_listbox(self, datab=registry_data):
        self.listbox.delete(0, tk.END)
        for app in datab:
            self.listbox.insert(tk.END, app['name'])

    def search_passwords(self, event=None):
        search = self.search_var.get().strip()
        '''if search_query.startswith('#'):
            self.search_by_tag(search_query[1:])
        else:
            self.populate_listbox(search_query)'''
        names, tags = dbms.parse_input(search)
        print(names, tags)
        entries = dbms.search_name_tag(names, tags, registry_data)
        print(entries.all())
        self.populate_listbox(entries.all())
        registry_data.drop_table('search')

    def on_select(self, event):
        selected_item = self.listbox.curselection()
        print(selected_item)
        if selected_item:
            app_name = self.listbox.get(selected_item[0])
            print(app_name)
            app = registry_data.search(where('name') == app_name)
            app = app[0]

            key = enc.derive_key_pbkdf2(master_pass, app['salt'])

            self.name_entry.delete(0, tk.END)
            self.tag_entry.delete(0, tk.END)
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)

            print(app['name'])
            self.name_entry.insert(0, app['name'])
            print(app['name'])
            self.tag_entry.insert(0, app['tag'])
            print(app['tag'])
            self.username_entry.insert(0, app['username'])
            print(app['username'])
            self.password_entry.insert(0, enc.decrypt_passwd(key, app['password'], app['iv']))
            print(app['password'])

    def save_value(self):
        name = self.name_entry.get().strip()
        tag = self.tag_entry.get()
        username = self.username_entry.get().strip()
        if self.should_gen == True:
            password = generator.gen_random_passwd(16, self.use_chars, self.use_nums, self.use_spl)
        else:
            password = self.password_entry.get().strip()
        
        alert, strength, feedback = generator.check_strength(password)
        entry = dbms.ask_passwd(name, username, password, tag)
        entry.strength = strength
        if len(entry.tag) == 0:
            entry.tag = tag.split()

        # Validate inputs
        if not name or not username or not password:
            messagebox.showwarning("Input Error", "All fields must be filled!")
            return

        registry_data.remove(where('name') == name)
        dbms.add_passwd(registry_data, entry, master_pass)
        messagebox.showinfo("Success", f"Details for {name} saved successfully!")

def mainloop_tk():
    root = tk.Tk()  # Create the main application root
    root.withdraw()  # Hide the root window until login is done
    login_window = LoginWindow(root)  # Create login window

    login_window.protocol("WM_DELETE_WINDOW", root.quit)  # If login window is closed, quit the app
    login_window.mainloop()

mainloop_tk()