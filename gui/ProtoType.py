import tkinter as tk
from tkinter import ttk, messagebox
from collections import Counter
from PIL import Image, ImageTk
import os


def evaluate_password_strength(password):
    if len(password) < 6:
        return "Weak"
    elif len(password) >= 6 and len(password) < 10:
        return "Moderate"
    else:
        return "Strong"

email_origin = "0" # the same as the below do what u want
master_pass = "0" # set ur jason file and define it as master_pass
otp_origin = "0"  # this for OTP idk what u will do for it

# Sample registry data
registry_data = {
    "Reddit": {"name":"Reddit","tag":"#app","username": "user_reddit", "password": "password123"},
    "Instagram": {"name":"Instagram","tag":"#app","username": "user_instagram", "password": "insta_password"},
    "Google": {"name":"Google","tag":"#website","username": "user_google", "password": "google_pass"},
    "Microsoft": {"name":"Microsoft","tag":"#website","username": "user_microsoft", "password": "ms_password"},
}


class LoginWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("HexaVault - Login")
        self.geometry("400x250")

        script_dire3 = os.path.dirname(os.path.abspath(__file__))
        self.logo = ImageTk.PhotoImage(Image.open(os.path.join(script_dire3, "logo_B.png")).resize((20, 25)))

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
        script_dir = os.path.dirname(os.path.abspath(__file__))
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
        self.add_button.pack(pady=17)

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
        script_dir = os.path.dirname(os.path.abspath(__file__))
        theme_file = os.path.join(script_dir, "azure.tcl")
        if os.path.exists(theme_file):
            self.tk.call("source", theme_file)
            self.tk.call("set_theme", "dark")  # You can choose between "light" and "dark"
        else:
            print(f"Theme file {theme_file} not found. Using default theme.")

    def add_account(self):
        email = self.email_entry.get()
        masterp = self.password_entry.get()

        if not masterp or not email or masterp != master_pass or email!= email_origin:
            messagebox.showwarning("Input Error", "password or Email is incorrect. Please try again.")
            return

        if masterp == master_pass:
            print(f"master password = {masterp}")  # where "masterp" is the variable containing the master password you get from text box
            self.destroy()
            DualFA(self.copy_image, self.search_icons)

class DualFA(tk.Tk):
    def __init__(self, copy_image, search_icons, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title("Dual-Factor Authentication")
        self.geometry("400x200")
        self.copy_image = copy_image
        self.search_icons = search_icons

        # Load Azure theme
        self.load_azure_theme()

        tk.Label(self, text="Enter the OTP").pack(pady=25)
        self.dual_fa_entry = tk.Entry(self, width=40)
        self.dual_fa_entry.pack(pady=5)

        self.add_button = ttk.Button(self, text="Login", command=self.check_otp)
        self.add_button.pack(pady=10)

    def load_azure_theme(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
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
            MainPage(self.copy_image, self.search_icons)  # Modified to pass the search_icons image


class MainPage(tk.Tk):
    def __init__(self, copy_image, search_icons, *args, **kwargs):  # Modified
        super().__init__(*args, **kwargs)
        self.title("HexaVault")
        self.geometry("500x360")
        self.copy_image = copy_image  # Store the copy_image in the class (Modified)
        self.search_icons = search_icons  # Store the search_icons in the class (Modified)

        self.load_azure_theme()

        script_dir = os.path.dirname(os.path.abspath(__file__))
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
        script_dir = os.path.dirname(os.path.abspath(__file__))
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

        all_passwords = []

        for category, data in registry_data.items():
            if isinstance(data, dict):
                for item, password in data.items():
                    strength = evaluate_password_strength(password)
                    if strength == "Weak":
                        weak_count += 1
                    elif strength == "Moderate":
                        moderate_count += 1
                    elif strength == "Strong":
                        strong_count += 1

        # Count repeated passwords using Counter
        password_counts = Counter(all_passwords)
        repeated_passwords = sum(1 for count in password_counts.values() if count > 1)

        # Update the dashboard labels with values
        self.repeated_passwords_label.config(text=f"Repeated Passwords\n{repeated_passwords}")
        self.weak_passwords_label.config(text=f"Weak Passwords\n{weak_count}")
        self.moderate_passwords_label.config(text=f"Moderate Passwords\n{moderate_count}")
        self.strong_passwords_label.config(text=f"Strong Passwords\n{strong_count}")

    def import_passwords(self):
        messagebox.showinfo("Success", "Imported successfully!")  # replace it later with actual import logic

    def export_passwords(self):
        messagebox.showinfo("Success", "Exported successfully!")   # replace it later with actual export logic

    def open_add_password_window(self, copy_image, search_icons):
        AddPasswordWindow(self, copy_image, search_icons)          #opens AddPasswordWindow

    def open_pass(self, eye_open, eye_closed, copy_image, search_icons):
        HomePage(self, eye_open, eye_closed, copy_image, search_icons)              # opens HomePage


# noinspection PyTypeChecker
class AddPasswordWindow(tk.Toplevel):
    def __init__(self, parent, copy_image, search_icons):
        super().__init__()
        self.title("Add New Password")
        self.geometry("450x330")
        self.copy_image = copy_image
        self.search_icons = search_icons
        self.parent = parent

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

        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.eye_open_image2 = ImageTk.PhotoImage(Image.open(os.path.join(script_dir, "View(1).png")).resize((20, 20)))
        self.eye_closed_image2 = ImageTk.PhotoImage(Image.open(os.path.join(script_dir, "Hide(1).png")).resize((20, 20)))

        # Create the eye button (as a Label) and keep reference
        self.eye_button = tk.Label(password_frame, image=self.eye_closed_image2, cursor="hand2")
        self.eye_button.grid(row=0, column=1, padx=3)
        self.eye_button.bind("<Button-1>", self.toggle_password)

        # Save button
        self.save_button = ttk.Button(self, text="Save", command=self.save_password)
        self.save_button.grid(row=10, column=1, padx=10, pady=15)

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

    def save_password(self):
        # Retrieve data from entries
        name = self.name_entry.get().strip()
        tag = self.tag_entry.get()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        # Validate inputs
        if not name or not username or not password:
            messagebox.showwarning("Input Error", "All fields must be filled!")
            return

        registry_data[name] = {
            "name": name,
            "Web/APP": name,
            "tag" : tag,
            "username": username,
            "password": password
        }

        # Notify user and close window
        messagebox.showinfo("Success", "Password added successfully!")
        self.destroy() # Refresh the listbox in HomePage


class HomePage(tk.Toplevel):
    def __init__(self, parent, eye_open_image, eye_closed_image, copy_image, search_icons):
        super().__init__()
        self.title("HexaVault")
        self.geometry("600x400")
        self.parent = parent

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

    def copy_to_clipboard(self, event=None):
        self.clipboard_clear()
        self.clipboard_append(self.password_entry.get())
        messagebox.showinfo("Info", "Password copied to clipboard!")

    def populate_listbox(self, search_query=None):
        self.listbox.delete(0, tk.END)
        for app in registry_data:
            if search_query is None or search_query.lower() in app.lower():
                self.listbox.insert(tk.END, app)

    def search_by_tag(self, tag):
        self.listbox.delete(0, tk.END)
        for app, data in registry_data.items():
            stored_tag = data.get("tag", "").lower()
            # Check if the search tag is a substring of the stored tag
            if tag.lower() in stored_tag:
                self.listbox.insert(tk.END, app)

    def search_passwords(self, event=None):
        search_query = self.search_var.get().strip()
        if search_query.startswith('#'):
            self.search_by_tag(search_query[1:])
        else:
            self.populate_listbox(search_query)

    def on_select(self, event):
        selected_item = self.listbox.curselection()
        if selected_item:
            app_name = self.listbox.get(selected_item[0])
            credentials = registry_data.get(app_name, {})

            self.name_entry.delete(0, tk.END)
            self.tag_entry.delete(0, tk.END)
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)

            self.name_entry.insert(0, credentials.get("name", ""))
            self.tag_entry.insert(0, credentials.get("tag", ""))
            self.username_entry.insert(0, credentials.get("username", ""))
            self.password_entry.insert(0, credentials.get("password", ""))

    def save_value(self):
        name = self.name_entry.get().strip()
        tag = self.tag_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        # Validate inputs
        if not name or not username or not password:
            messagebox.showwarning("Input Error", "All fields must be filled!")
            return

        registry_data[name] = {
            "name": name,
            "Web/APP": name,
            "tag": tag,
            "username": username,
            "password": password
        }
        messagebox.showinfo("Success", f"Details for {name} saved successfully!")


if __name__ == "__main__":
    root = tk.Tk()  # Create the main application root
    root.withdraw()  # Hide the root window until login is done
    login_window = LoginWindow(root)  # Create login window

    login_window.protocol("WM_DELETE_WINDOW", root.quit)  # If login window is closed, quit the app
    login_window.mainloop()
