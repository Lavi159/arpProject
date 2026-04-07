import customtkinter as ctk
from PIL import Image
import os
import threading
from tkinter import messagebox
from client import Client

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

class ClientGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.client = Client()
        self.title("ARP Defense System - Client Login")
        self.geometry("750x600")

        image_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "images")

        try:
            dragon_image = ctk.CTkImage(
                light_image=Image.open(os.path.join(image_path, "dragon_icon.png")),
                dark_image=Image.open(os.path.join(image_path, "dragon_icon.png")),
                size=(280, 280)
            )
            self.image_label = ctk.CTkLabel(self, image=dragon_image, text="")
            self.image_label.pack(pady=10)
        except Exception as e:
            print(f"Could not load image: {e}")

        self.title_label = ctk.CTkLabel(
            self,
            text="WELCOME TO CLIENT",
            font=("Showcard Gothic", 40),
            text_color="#FF4500"
        )
        self.title_label.pack(pady=25)

        self.input_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.input_frame.pack(pady=20)

        ctk.CTkLabel(self.input_frame, text="USERNAME:", font=("Showcard Gothic", 16)).grid(
            row=0, column=0, pady=10, sticky="e"
        )
        self.username_entry = ctk.CTkEntry(
            self.input_frame, width=320, height=35, placeholder_text="Enter username..."
        )
        self.username_entry.grid(row=0, column=1, padx=15)

        ctk.CTkLabel(self.input_frame, text="PASSWORD:", font=("Showcard Gothic", 16)).grid(
            row=1, column=0, pady=10, sticky="e"
        )
        self.password_entry = ctk.CTkEntry(
            self.input_frame, width=320, height=35, show="*", placeholder_text="Enter password..."
        )
        self.password_entry.grid(row=1, column=1, padx=15)

        self.button_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.button_frame.pack(pady=15)

        self.log_button = ctk.CTkButton(
            self.button_frame, text="LOG", width=140, height=40,
            fg_color="white", text_color="black", font=("Showcard Gothic", 18),
            corner_radius=10, command=self.login_action
        )
        self.log_button.grid(row=0, column=0, padx=25)

        self.sign_button = ctk.CTkButton(
            self.button_frame, text="SIGN", width=140, height=40,
            fg_color="white", text_color="black", font=("Showcard Gothic", 18),
            corner_radius=10, command=self.signup_action
        )
        self.sign_button.grid(row=0, column=1, padx=25)

        self.quit_button = ctk.CTkButton(
            self, text="QUIT", width=110, height=35,
            fg_color="#444444", hover_color="#666666", text_color="white",
            font=("Showcard Gothic", 14), corner_radius=8, command=self.quit_action
        )
        self.quit_button.pack(side="bottom", pady=25)

    def show_message(self, title, message):
        """מעדכן את הממשק עם הודעה מהשרת"""
        def update_ui():
            if title == "Success":
                messagebox.showinfo(title, message)
            else:
                messagebox.showerror(title, message)
        
        # שימוש ב-after מבטיח שההודעה תקפוץ מה-Thread הראשי של ה-GUI
        self.after(0, update_ui)

    def login_action(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return

        # כאן הוספנו את self.show_message כ-callback
        threading.Thread(
            target=self.client.connect_to_server,
            args=(username, password, "1", None, self.show_message),
            daemon=True
        ).start()

    def signup_action(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return

        # כאן הוספנו את self.show_message כ-callback
        threading.Thread(
            target=self.client.connect_to_server,
            args=(username, password, "2", None, self.show_message),
            daemon=True
        ).start()

    def quit_action(self):
        self.destroy()

if __name__ == "__main__":
    app = ClientGUI()
    app.mainloop()