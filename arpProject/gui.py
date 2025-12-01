import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
from db_tools import Db_Tools 

class ServerGUI:
    def __init__(self):
        self.db_tools = Db_Tools() 
        self.db_conn = None 
        self.root = None
        self.tree = None
        self.last_update_label = None

    def run_gui(self, db_conn):
        self.db_conn = db_conn
        
        self.root = tk.Tk()
        self.root.title("ARP Detector Server - Client View")
        
        self.root.geometry("1100x550")
        self.root.configure(bg="#2c3e50") 
        
        header_frame = tk.Frame(self.root, bg="#34495e")
        header_frame.pack(side="top", fill="x", padx=10, pady=10)
        tk.Label(header_frame, text="🛡️ Connected Agents (Clients Table)", 
                 font=("Segoe UI", 18, "bold"), fg="white", bg="#34495e").pack(pady=5)

        self.main_frame = tk.Frame(self.root, bg="#ecf0f1")
        self.main_frame.pack(expand=True, fill="both", padx=10, pady=10)

        self.load_clients_table()
        
        self.root.mainloop()
        
    def trigger_refresh(self):
        if self.root:
            self.root.after(0, self.update_table, "clients")

    def clear_frame(self, frame):
        for widget in frame.winfo_children():
            widget.destroy()
            
    def clear_and_refresh(self):
        if messagebox.askyesno("Confirm Clear", "Are you sure you want to DELETE ALL client entries?"):
            try:
                self.db_tools.delete_all_rows(self.db_conn, "clients")
                self.update_table("clients")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear clients table: {e}")

    def load_clients_table(self):
        self.clear_frame(self.main_frame)
        
        columns = ("ID", "PasswordHash", "Hostname", "IP", "LastSeen", "DDoSStatus", "JoinDate")
        
        style = ttk.Style()
        style.theme_use("clam") 
        style.configure("Treeview.Heading", font=('Segoe UI', 10, 'bold'), background="#3498db", foreground="white")
        style.configure("Treeview", font=('Segoe UI', 9), rowheight=20)
        style.map('Treeview', background=[('selected', '#5fa8d3')])

        tree_frame = tk.Frame(self.main_frame)
        tree_frame.pack(pady=10, padx=10, expand=True, fill='both')
        
        tree_scroll = ttk.Scrollbar(tree_frame)
        tree_scroll.pack(side="right", fill="y")

        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=15, yscrollcommand=tree_scroll.set)
        tree_scroll.config(command=self.tree.yview)
        
        self.tree.heading("ID", text="ID")
        self.tree.heading("PasswordHash", text="Password Hash")
        self.tree.heading("Hostname", text="Hostname")
        self.tree.heading("IP", text="IP Address")
        self.tree.heading("LastSeen", text="Last Seen")
        self.tree.heading("DDoSStatus", text="DDoS Status")
        self.tree.heading("JoinDate", text="Join Date")

        self.tree.column("ID", width=50, anchor='center')
        self.tree.column("PasswordHash", width=150, anchor='center')
        self.tree.column("Hostname", width=150, anchor='center')
        self.tree.column("IP", width=100, anchor='center')
        self.tree.column("LastSeen", width=140, anchor='center')
        self.tree.column("DDoSStatus", width=100, anchor='center')
        self.tree.column("JoinDate", width=140, anchor='center')
        
        self.tree.pack(expand=True, fill='both', side="left")

        status_frame = tk.Frame(self.main_frame, bg="#ecf0f1")
        status_frame.pack(pady=10)

        tk.Button(status_frame, text="🗑️ Clear & Refresh Clients", command=self.clear_and_refresh,
                  font=("Segoe UI", 11, "bold"), bg="#e74c3c", fg="white", activebackground="#c0392b").pack(side="left", padx=20)
        
        self.last_update_label = tk.Label(status_frame, text="Status: Ready", font=("Segoe UI", 9), bg="#ecf0f1", fg="#7f8c8d")
        self.last_update_label.pack(side="left", padx=10)
        
        self.update_table("clients")


    def update_table(self, table_name):
        if not self.db_conn or table_name != "clients":
            return

        try:
            rows = self.db_tools.get_all_rows(self.db_conn, table_name)
            self.tree.delete(*self.tree.get_children())
            
            for row in rows:
                if len(row) >= 7:
                    display_row = (
                        row[0], 
                        row[1], 
                        row[2], 
                        row[3], 
                        row[4], 
                        row[5], 
                        row[6]  
                    )
                    self.tree.insert("", "end", values=display_row)

            timestamp = time.strftime("%H:%M:%S")
            self.last_update_label.config(text=f"Last updated: {timestamp} | Total Clients: {len(rows)}", fg="#2c3e50")

        except Exception as e:
            self.last_update_label.config(text=f"DB Error! Failed to fetch: {e}", fg="red")