import customtkinter as ctk
from tkinter import ttk, messagebox
from PIL import Image
import os
from datetime import datetime
from db_tools import Db_Tools

COLOR_BG = "#050a10"
COLOR_ORANGE = "#FF4500"
COLOR_CYAN = "#00d4ff"
COLOR_SUCCESS = "#00FF41"
COLOR_DANGER = "#FF1744"


class ServerGUI:
    def __init__(self):
        self.root = None
        self.db_conn = None
        self.db_tools = Db_Tools()
        self.tree = None
        self.log_tree = None
        self.blocked_tree = None
        self.text_log_box = None
        self.log_queue = []
        self.base_path = os.path.dirname(os.path.abspath(__file__))
        self.image_path = os.path.join(self.base_path, "images")
        self.dragon_img_ctk = None
        self.hacker_img_ctk = None

    def run_gui(self, db_conn):
        self.db_conn = db_conn
        self.root = ctk.CTk()
        self.root.title("☠️ ARP DEFENSE - ELITE COMMAND CENTER ☠️")
        self.root.geometry("1400x900")
        self.root.configure(fg_color=COLOR_BG)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.load_assets()
        self.show_splash_screen()
        self.slow_refresh_cycle()
        self.root.mainloop()

    def slow_refresh_cycle(self):
        if self.root:
            self.trigger_refresh()
            self.root.after(60000, self.slow_refresh_cycle)

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Close Command Center?"):
            self.root.destroy()

    def load_assets(self):
        try:
            d_path = os.path.join(self.image_path, "dragon_icon.png")
            h_path = os.path.join(self.image_path, "hacker_icon.png")
            if os.path.exists(d_path) and os.path.exists(h_path):
                self.dragon_img_ctk = ctk.CTkImage(Image.open(d_path), size=(250, 250))
                self.hacker_img_ctk = ctk.CTkImage(Image.open(h_path), size=(400, 400))
        except Exception as e:
            print(f"Image assets missing: {e}")

    def clear_screen(self):
        self.tree = None
        self.log_tree = None
        self.blocked_tree = None
        self.text_log_box = None
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_splash_screen(self):
        self.clear_screen()
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        header = ctk.CTkFrame(self.root, fg_color="#001220", border_width=2, border_color=COLOR_ORANGE)
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=10)
        ctk.CTkLabel(header, text="ARP DEFENSE CENTER", font=("Showcard Gothic", 50), text_color=COLOR_ORANGE).pack(pady=5)

        vis_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        vis_frame.grid(row=1, column=0, sticky="nsew")
        vis_frame.grid_columnconfigure((0, 1, 2), weight=1)

        if self.dragon_img_ctk and self.hacker_img_ctk:
            img_list = [self.dragon_img_ctk, self.hacker_img_ctk, self.dragon_img_ctk]
            for i, img in enumerate(img_list):
                lbl = ctk.CTkLabel(vis_frame, image=img, text="")
                lbl.image = img
                lbl.grid(row=0, column=i)

        btn_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        btn_frame.grid(row=2, column=0, sticky="ew", pady=30)
        btn_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.add_button(btn_frame, "NETWORK CLIENTS", "DATABASE", 0, self.show_clients_view, COLOR_CYAN)
        self.add_button(btn_frame, "SECURITY EVENTS", "MONITOR", 1, self.show_events_view, COLOR_DANGER)
        self.add_button(btn_frame, "SERVER LOGS", "TERMINAL", 2, self.show_raw_logs_view, "#FFD700")
        self.add_button(btn_frame, "BLOCKED LIST", "FIREWALL", 3, self.show_blocked_ips_view, "#FF00FF")

    def add_button(self, parent, title, sub, col, cmd, color):
        f = ctk.CTkFrame(parent, width=300, height=120, fg_color="#0a1a2a", border_width=2, border_color=color)
        f.grid(row=0, column=col, padx=15)
        f.grid_propagate(False)
        btn = ctk.CTkButton(
            f,
            text=f"{title}\n> {sub}",
            font=("Consolas", 16, "bold"),
            fg_color="transparent",
            hover_color="#122c44",
            command=cmd
        )
        btn.pack(expand=True, fill="both")

    def show_clients_view(self):
        self.clear_screen()
        ctk.CTkButton(self.root, text="⬅ BACK", fg_color=COLOR_ORANGE, command=self.show_splash_screen).pack(anchor="nw", padx=20, pady=10)
        container = ctk.CTkFrame(self.root, fg_color=COLOR_BG)
        container.pack(expand=True, fill="both", padx=30, pady=20)
        cols = ("ID", "Hostname", "IP", "Last Seen", "DDoS Status", "Joined")
        self.tree = self.create_styled_tree(container, cols)
        self.refresh_db_data()

    def show_events_view(self):
        self.clear_screen()
        ctk.CTkButton(self.root, text="⬅ BACK", fg_color=COLOR_ORANGE, command=self.show_splash_screen).pack(anchor="nw", padx=20, pady=10)
        container = ctk.CTkFrame(self.root, fg_color=COLOR_BG)
        container.pack(expand=True, fill="both", padx=30, pady=20)

        cols = ("Time", "Hostname", "Status", "Victim IP", "Expected MAC", "Observed MAC")
        self.log_tree = self.create_styled_tree(container, cols)
        self.log_tree.tag_configure("SUSPECT", background="#8B0000", foreground="white")
        self.log_tree.tag_configure("OK", foreground=COLOR_SUCCESS)
        self.refresh_event_logs()

    def show_raw_logs_view(self):
        self.clear_screen()
        ctk.CTkButton(self.root, text="⬅ BACK", fg_color=COLOR_ORANGE, command=self.show_splash_screen).pack(anchor="nw", padx=20, pady=10)
        self.text_log_box = ctk.CTkTextbox(self.root, fg_color="black", text_color=COLOR_SUCCESS, font=("Consolas", 14))
        self.text_log_box.pack(expand=True, fill="both", padx=30, pady=20)

        for log in self.log_queue:
            self.text_log_box.insert("end", log + "\n")
        self.text_log_box.see("end")

    def create_styled_tree(self, parent, cols):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#0a1a2a", foreground="white", fieldbackground="#0a1a2a", rowheight=35)
        style.configure("Treeview.Heading", background="#002b4d", foreground=COLOR_CYAN, font=("Consolas", 12, "bold"))

        tree = ttk.Treeview(parent, columns=cols, show="headings")
        for col in cols:
            tree.heading(col, text=col.upper())
            if "MAC" in col.upper():
                tree.column(col, width=180, anchor="center")
            else:
                tree.column(col, anchor="center")

        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)

        tree.pack(side="left", expand=True, fill="both")
        scrollbar.pack(side="right", fill="y")
        return tree

    def write_to_log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.log_queue.append(log_entry)

        if len(self.log_queue) > 1000:
            self.log_queue.pop(0)

        if self.text_log_box and self.root:
            self.root.after(0, lambda: self.text_log_box.insert("end", log_entry + "\n"))
            self.root.after(0, lambda: self.text_log_box.see("end"))

    def refresh_event_logs(self):
        if not self.log_tree:
            return

        conn = None
        cursor = None
        try:
            conn = self.db_tools.initialize_database()
            cursor = conn.cursor()
            query = """
                SELECT
                    e.events_timestamp,
                    c.clients_hostname,
                    e.events_status,
                    e.events_victim_ip,
                    e.events_old_mac,
                    e.events_new_mac
                FROM events e
                LEFT JOIN clients c ON e.events_client_id = c.clients_id
                ORDER BY e.events_id DESC
            """
            cursor.execute(query)
            rows = cursor.fetchall()

            self.log_tree.delete(*self.log_tree.get_children())

            for row in rows:
                status_raw = str(row[2]).upper().strip() if row[2] is not None else "OK"

                if status_raw in ("SUSPECT", "DETECTED", "UNDER_ATTACK", "BLOCKED"):
                    display_status = "SUSPECT"
                    tag = "SUSPECT"
                else:
                    display_status = "OK"
                    tag = "OK"

                time_str = row[0].strftime("%Y-%m-%d %H:%M:%S") if row[0] else "N/A"
                hostname = row[1] if row[1] else "UNKNOWN"

                self.log_tree.insert(
                    "",
                    "end",
                    values=(
                        time_str,
                        hostname,
                        display_status,
                        row[3],
                        row[4],
                        row[5]
                    ),
                    tags=(tag,)
                )

        except Exception as e:
            print(f"Refresh Events Error: {e}")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    def refresh_db_data(self):
        if not self.tree:
            return

        conn = None
        cursor = None
        try:
            conn = self.db_tools.initialize_database()
            cursor = conn.cursor()
            query = """
                SELECT
                    clients_id,
                    clients_hostname,
                    clients_ip,
                    clients_last_seen,
                    clients_ddos_status,
                    clients_created_at
                FROM clients
                ORDER BY clients_id DESC
            """
            cursor.execute(query)
            rows = cursor.fetchall()

            for item in self.tree.get_children():
                self.tree.delete(item)

            for row in rows:
                display_row = list(row)

                display_row[4] = "True" if bool(display_row[4]) else "False"

                if isinstance(display_row[3], datetime):
                    display_row[3] = display_row[3].strftime("%H:%M:%S")
                if isinstance(display_row[5], datetime):
                    display_row[5] = display_row[5].strftime("%Y-%m-%d")

                self.tree.insert("", "end", values=display_row)

        except Exception as e:
            print(f"[-] Database Refresh Error: {e}")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
                
    def trigger_event_alert(self, client_name, status, victim_ip):
        if self.root:
            self.trigger_refresh()

        if status == "SUSPECT":
            messagebox.showwarning(
                "⚠️ SECURITY ALERT",
                f"ARP Spoofing detected on client: {client_name}!\nTarget IP: {victim_ip}"
            )

    def trigger_ddos_alert(self, attacker_ip):
        if self.root:
            self.trigger_refresh()
            messagebox.showerror(
                "🚨 DDoS ATTACK DETECTED",
                f"CRITICAL: High connection volume from IP: {attacker_ip}\n\n"
                f"The system has automatically BLOCKED this IP and terminated all active sessions."
            )

    def trigger_refresh(self):
        if self.root:
            self.root.after(0, self._safe_refresh)

    def _safe_refresh(self):
        try:
            if self.tree and self.tree.winfo_exists():
                self.refresh_db_data()

            if self.log_tree and self.log_tree.winfo_exists():
                self.refresh_event_logs()

            if self.blocked_tree and self.blocked_tree.winfo_exists():
                self.refresh_blocked_ips()
        except Exception as e:
            print(f"Safe refresh skipped: {e}")

    def show_blocked_ips_view(self):
        self.clear_screen()
        ctk.CTkButton(self.root, text="⬅ BACK", fg_color=COLOR_ORANGE, command=self.show_splash_screen).pack(anchor="nw", padx=20, pady=10)

        container = ctk.CTkFrame(self.root, fg_color=COLOR_BG)
        container.pack(expand=True, fill="both", padx=30, pady=10)

        ctk.CTkLabel(
            container,
            text="🚫 SYSTEM FIREWALL - BLOCKED ADDRESSES",
            font=("Showcard Gothic", 25),
            text_color=COLOR_DANGER
        ).pack(pady=10)

        cols = ("IP Address", "Blocked At", "Reason")
        self.blocked_tree = self.create_styled_tree(container, cols)

        unblock_btn = ctk.CTkButton(
            self.root,
            text="🔓 UNBLOCK SELECTED IP",
            fg_color="#2E0854",
            hover_color=COLOR_SUCCESS,
            font=("Consolas", 16, "bold"),
            height=45,
            command=self.unblock_selected_ip
        )
        unblock_btn.pack(pady=20)

        self.refresh_blocked_ips()

    def unblock_selected_ip(self):
        selected_item = self.blocked_tree.selection()
        if not selected_item:
            messagebox.showwarning("Selection Error", "Please select an IP from the list first!")
            return

        ip_to_unblock = self.blocked_tree.item(selected_item)["values"][0]

        if messagebox.askyesno("Confirm", f"Unblock IP {ip_to_unblock}?"):
            conn = None
            cursor = None
            try:
                conn = self.db_tools.initialize_database()
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE clients SET clients_ddos_status = FALSE WHERE clients_ip = %s",
                    (ip_to_unblock,)
                )
                conn.commit()

                self.write_to_log(f"ADMIN: IP {ip_to_unblock} unblocked (DDoS status set to False).")
                self.refresh_blocked_ips()
                self.trigger_refresh()
                messagebox.showinfo("Success", f"IP {ip_to_unblock} status reset to Normal.")

            except Exception as e:
                if conn:
                    conn.rollback()
                messagebox.showerror("DB Error", f"Failed to update status: {e}")
            finally:
                if cursor:
                    cursor.close()
                if conn:
                    conn.close()

    def refresh_blocked_ips(self):
        if not self.blocked_tree:
            return

        conn = None
        cursor = None
        try:
            if not self.blocked_tree.winfo_exists():
                return

            conn = self.db_tools.initialize_database()
            cursor = conn.cursor()
            query = """
                SELECT clients_ip, MAX(clients_last_seen), 'DDoS Attack Detected' as reason
                FROM clients
                WHERE clients_ddos_status = TRUE
                GROUP BY clients_ip
            """
            cursor.execute(query)
            rows = cursor.fetchall()

            self.blocked_tree.delete(*self.blocked_tree.get_children())

            for row in rows:
                display_row = list(row)
                if isinstance(display_row[1], datetime):
                    display_row[1] = display_row[1].strftime("%H:%M:%S")

                self.blocked_tree.insert("", "end", values=display_row)

        except Exception as e:
            print(f"Error refreshing blocked list: {e}")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()