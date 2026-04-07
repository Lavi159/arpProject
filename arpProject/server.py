import socket
import threading
import json
from datetime import datetime, timezone
from constants import HOST, PORT, KEYS_DIR, MAX_TOTAL_CONNECTIONS, MAX_CONNECTIONS_PER_IP
from crypto_utils import Crypto_utils
from db_tools import Db_Tools
from tools import Tools
from gui import ServerGUI




class Server:
    def __init__(self):
        self.gui = None
        self.log_message("Server is running")
        self._seq_lock = threading.Lock()
        self._seq_counter = 0
        
        self.ip_counts = {}
        self.total_connections = 0  
        self._conn_lock = threading.Lock() 

        self.clients_info = {}
        self.db_tools = Db_Tools()  
        self.Crypto_utils = Crypto_utils()
        self.tools = Tools()
        self.priv_path, self.pub_path = self.Crypto_utils.generate_rsa_keys(KEYS_DIR, "server")
        self.private_key = self.Crypto_utils.load_key(self.priv_path)
        self.public_key = self.Crypto_utils.load_key(self.pub_path)         

    
    def _authenticate_client(self, db, client_sckt, aes_key, addr, option_signing):
        clients_ip, clients_port = addr
        clients_last_seen = datetime.now()
        clients_ddos_status = False

        if option_signing not in ["1", "2"]:
            self.Crypto_utils.send_encrypted(client_sckt, aes_key, "ERROR: Invalid option")
            client_sckt.close()
            return False, None, None
        
        client_username = self.Crypto_utils.recv_encrypted(client_sckt, aes_key)
        client_password = self.Crypto_utils.recv_encrypted(client_sckt, aes_key)
        hashed_password = self.tools.get_hash_value(client_password)
        
        clients_hostname = client_username
        is_valid_user = self.db_tools.is_db_in_table(db, "clients", clients_hostname, hashed_password)

        if option_signing == "2":
            if is_valid_user:
                self.log_message(f"Signup FAILED: User '{clients_hostname}' already exists.")
                self.Crypto_utils.send_encrypted(client_sckt, aes_key, "ERROR: User already exists")
                client_sckt.close()
                return False, None, None
            
            self.log_message(f"New client signed up: {clients_hostname}")
            self.db_tools.insert_client_info(
                db, 
                password_hashed=hashed_password,
                hostname=clients_hostname, 
                ip=clients_ip, 
                last_seen=clients_last_seen, 
                created_at=clients_last_seen
            )
            self.Crypto_utils.send_encrypted(client_sckt, aes_key, "SUCCESS: User signed up.")
            if self.gui:
                self.gui.trigger_refresh()
            return True, clients_hostname, hashed_password

        elif option_signing == "1":
            if not is_valid_user:
                self.log_message(f"Login FAILED: Invalid credentials for user '{clients_hostname}'.")
                self.Crypto_utils.send_encrypted(client_sckt, aes_key, "ERROR: Invalid username or password")
                client_sckt.close()
                return False, None, None
            
            self.log_message(f"Login SUCCESS: User '{clients_hostname}' updated.")
            self.db_tools.update_client_entry(
    db,
    clients_hostname,
    clients_ip,
    clients_last_seen,
    hashed_password
)
            self.Crypto_utils.send_encrypted(client_sckt, aes_key, "SUCCESS: Logged in.")
            if self.gui:
                self.gui.trigger_refresh()
            return True, clients_hostname, hashed_password

        return False, None, None
    
    
    def next_seq(self):
        with self._seq_lock:
            self._seq_counter += 1
            return self._seq_counter

    def now_iso(self):
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    def log_message(self, message):
        print(message) 
        if self.gui and self.gui.root:
            self.gui.root.after(0, lambda: self.gui.write_to_log(message))
    
    def create_defense_message(self, ip_server, port_server):
        defense_command = {
                    "type": "command",
                    "seq": self.next_seq(),
                    "timestamp": self.now_iso(),
                    "sender": {"ip": ip_server, "port": port_server},
                    "body": {
                        "action": "run_defense_daemon", 
                        "params": { 
                            "daemon_name": "arpon",
                            "mode": "SARPI"
                        }
                    }
                }
        return json.dumps(defense_command)
    
        
    def handle_client(self, client_sckt, addr):
        db = self.db_tools.initialize_database()
        ip_address = addr[0]  # שמירת ה-IP לבדיקות חסימה
        if self.db_tools.is_ip_blocked(db, ip_address):
            self.log_message(f"[!] Blocked IP {ip_address} tried to connect. Denied.")
            client_sckt.close()
            return
        ip_server = client_sckt.getsockname()[0]
        port_server = client_sckt.getsockname()[1]
        
        authenticated_hostname = None
        authenticated_password_hash = None
        aes_key = None

        try:
            self.log_message(f"[+] Connected by {addr}")
            client_sckt.settimeout(15)
            
            # שלב ה-Handshake (RSA)
            client_pub_bytes = self.Crypto_utils.recv_framed(client_sckt)
            if not client_pub_bytes:
                return
                
            client_pub = self.Crypto_utils.load_key_from_str(client_pub_bytes.decode())
            self.Crypto_utils.send_framed(client_sckt, self.public_key.export_key())

            # שלב החלפת מפתח AES
            encrypted_aes = self.Crypto_utils.recv_framed(client_sckt)
            if not encrypted_aes:
                return        
            
            aes_key = self.Crypto_utils.rsa_decrypt(self.private_key, encrypted_aes)
            print("[*] Session AES key established")
            
            option_signing = self.Crypto_utils.recv_encrypted(client_sckt, aes_key)
            
            if option_signing != "3":
                # אימות מול ה-DB
                success, hostname, password_hash = self._authenticate_client(
                    db, client_sckt, aes_key, addr, option_signing
                )

                if not success:
                    return

                # קבלת מידע טכני מהלקוח
                client_info_raw = self.Crypto_utils.recv_encrypted(client_sckt, aes_key)
                if not client_info_raw:
                    return

                client_info = json.loads(client_info_raw)
                
                # עדכון הדיקשנרי של השרת - הוספתי last_known_ip לצורך ניהול חסימות
                self.clients_info[hostname] = {
                    "gateway_ip": client_info.get("gateway_ip"),
                    "gateway_mac": client_info.get("gateway_mac"),
                    "interface": client_info.get("interface"),
                    "last_known_ip": ip_address 
                }

                authenticated_hostname = hostname
                authenticated_password_hash = password_hash
                
                if self.gui:
                    self.gui.trigger_refresh()

                # --- לולאת ההאזנה המרכזית ---
                while True:

                    try:
                        msg_raw = self.Crypto_utils.recv_encrypted(client_sckt, aes_key)
                        if not msg_raw:
                            self.log_message(f"[-] Client {authenticated_hostname} disconnected.")
                            break

                        msg = json.loads(msg_raw)
                        mtype = msg.get("type")

                        if mtype == "event":
                            client_status = msg.get("status", "unknown")
                            victim_ip = msg.get("victim_ip", "unknown")
                            
                            is_attacked = (client_status == "SUSPECT")                            
                            if is_attacked:
                                self.log_message(f"[ALERT] Attack detected from {authenticated_hostname}: {client_status}")
                                self.db_tools.update_client_status(db, authenticated_hostname, "SUSPECT")
                                client_id = self.db_tools.get_client_id_by_hostname(db, authenticated_hostname)
                                if client_id:
                                    self.db_tools.insert_event(
                                        mydb=db,
                                        events_client_id=client_id,
                                        events_interface=msg.get("interface") or "N/A",
                                        events_victim_ip=victim_ip,
                                        events_old_mac=msg.get("expected_mac") or "00:00:00:00:00:00",
                                        events_new_mac=msg.get("observed_mac") or "00:00:00:00:00:00",
                                        events_action="blocked",
                                        events_method="arpon", 
                                        events_status=client_status,
                                        events_ddos_status="under_attack"
                                    )
                                    if self.gui:
                                        self.gui.trigger_refresh()
                                    cmd = self.create_defense_message(ip_server, port_server)
                                    self.Crypto_utils.send_encrypted(client_sckt, aes_key, cmd)
                                    
                                if self.gui:
                                    self.gui.root.after(0, lambda h=authenticated_hostname, s=client_status, v=victim_ip: 
                                                       self.gui.trigger_event_alert(h, s, v))
                            else:
                                self.log_message(f"[INFO] {authenticated_hostname} reports system is clean.")

                            if self.gui:
                                self.gui.trigger_refresh()

                        elif mtype == "response":
                            self.log_message(f"[RESPONSE] from {authenticated_hostname}: {json.dumps(msg)}")
                            if self.gui:
                                self.gui.trigger_refresh()

                    except socket.timeout:
                        continue
                    except OSError as e:
                        if getattr(e, "winerror", None) == 10038:
                            self.log_message(f"[-] Client {authenticated_hostname or addr} socket closed.")
                        else:
                            print(f"[!] Error in receive loop: {e}")
                        break
                    except Exception as e:
                        print(f"[!] Error in receive loop: {e}")
                        break
            else:
                return

        except Exception as e:
            print(f"[!] Critical error handling client {addr}: {e}")

        finally:
            with self._conn_lock:
                if ip_address in self.ip_counts:
                    if client_sckt in self.ip_counts[ip_address]:
                        self.ip_counts[ip_address].remove(client_sckt)
                        self.total_connections -= 1
            
            if authenticated_hostname in self.clients_info:
                del self.clients_info[authenticated_hostname]
            
            if self.gui:
                self.gui.trigger_refresh()
            try:
                if db: db.close()
                client_sckt.close()
            except:
                pass
        

    def _listen_loop(self):
        s = socket.socket()
        try:
            s.bind((HOST, PORT))
            s.listen()
            
            while True:
                client_sckt, addr = s.accept()
                ip = addr[0]

                with self._conn_lock:
                    temp_db = self.db_tools.initialize_database()
                    is_blocked = self.db_tools.is_ip_blocked(temp_db, ip)
                    temp_db.close()

                    if is_blocked:
                        self.log_message(f"[!] Access Denied: {ip} is blocked in Database.")
                        client_sckt.close()
                        continue

                    if self.total_connections >= MAX_TOTAL_CONNECTIONS:
                        self.log_message(f"[!] Server full ({MAX_TOTAL_CONNECTIONS}). Denied: {ip}")
                        client_sckt.close()
                        continue
                    
                    current_sockets = self.ip_counts.get(ip, [])
                    if len(current_sockets) >= MAX_CONNECTIONS_PER_IP:
                        self._handle_ddos(ip, current_sockets, client_sckt)
                        continue

                    if ip not in self.ip_counts:
                        self.ip_counts[ip] = []
                    self.ip_counts[ip].append(client_sckt)
                    self.total_connections += 1

                threading.Thread(target=self.handle_client, args=(client_sckt, addr), daemon=True).start()
                
        except Exception as e:
            print(f"[!] Server Listen Loop Error: {e}")
        finally:
            s.close()

    def _handle_ddos(self, ip, current_sockets, new_sckt):
        self.log_message(f"[!!!] DDoS detected from {ip}! Blocking...")
        
        temp_db = self.db_tools.initialize_database()
        self.db_tools.update_ddos_status_by_ip(temp_db, ip, True)
        temp_db.close()

        if self.gui:
            self.gui.root.after(0, lambda: self.gui.trigger_ddos_alert(ip))
            self.gui.trigger_refresh()

        for sckt in list(current_sockets):
            try:
                sckt.shutdown(socket.SHUT_RDWR)
            except:
                pass
            try:
                sckt.close()
            except:
                pass

        try:
            new_sckt.shutdown(socket.SHUT_RDWR)
        except:
            pass
        try:
            new_sckt.close()
        except:
            pass
        
        with self._conn_lock:
            num_closed = len(current_sockets)
            self.total_connections = max(0, self.total_connections - num_closed)
            self.ip_counts[ip] = []
            
        self.log_message(f"[=] All {num_closed} connections from {ip} have been terminated.")
        
    def start_server(self):
        self.gui = ServerGUI()
        gui_db = self.db_tools.initialize_database()
        
        server_thread = threading.Thread(target=self._listen_loop, daemon=True)
        server_thread.start()
        
        print(f"[*] Server thread started. Listening on {HOST}:{PORT}")

        self.gui.run_gui(gui_db)

if __name__ == "__main__":
    my_server = Server()
    my_server.start_server()
