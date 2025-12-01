import socket
import threading
import json
from datetime import datetime, timezone
from constants import HOST, PORT, KEYS_DIR
from crypto_utils import Crypto_utils
from db_tools import Db_Tools
from tools import Tools
from gui import ServerGUI

IP_VICTIM = "192.168.1.1"
MAC_SUS = "00-B0-D0-63-C2-26"
_seq_counter = 0



class Server:
    def __init__(self):
        print("Server is running")
        self.gui = None
        self.db_tools = Db_Tools()  
        self.Crypto_utils = Crypto_utils()
        self.tools = Tools()
        self.priv_path, self.pub_path = self.Crypto_utils.generate_rsa_keys(KEYS_DIR, "server")
        self.private_key = self.Crypto_utils.load_key(self.priv_path)
        self.public_key = self.Crypto_utils.load_key(self.pub_path)          

    
    def _authenticate_client(self, db, client_sckt, aes_key, addr, option_signing):
        clients_ip, clients_port = addr
        clients_last_seen = datetime.now()
        clients_ddos_status = 'normal'

        if option_signing not in ["1", "2"]:
            self.Crypto_utils.send_encrypted(client_sckt, aes_key, "ERROR: Invalid option")
            client_sckt.close()
            return False, None, None
        
        client_username = self.Crypto_utils.recv_encrypted(client_sckt, aes_key)
        client_password = self.Crypto_utils.recv_encrypted(client_sckt, aes_key)
        hashed_password = self.tools.get_hash_value(client_password)
        
        clients_hostname = client_username

        is_valid_user = self.db_tools.is_db_in_table(db, "clients", clients_hostname, hashed_password)

        if option_signing == "2":  # Signup
            if is_valid_user:
                print(f"Signup FAILED: User '{clients_hostname}' already exists with this password.")
                self.Crypto_utils.send_encrypted(client_sckt, aes_key, "ERROR: User already exists")
                client_sckt.close()
                return False, None, None
            
            print(f"New client signed up: {clients_hostname}. Inserting entry.")
            self.db_tools.insert_client_info(
                db, 
                hashed_password,
                clients_hostname, 
                clients_ip, 
                clients_last_seen, 
                clients_ddos_status,
                clients_last_seen
            )
            self.Crypto_utils.send_encrypted(client_sckt, aes_key, "SUCCESS: User signed up and logged in.")
            return True, clients_hostname, hashed_password

        elif option_signing == "1":  # Login
            if not is_valid_user:
                print(f"Login FAILED: Invalid credentials for user '{clients_hostname}'.")
                self.Crypto_utils.send_encrypted(client_sckt, aes_key, "ERROR: Invalid username or password")
                client_sckt.close()
                return False, None, None
            
            print(f"Login SUCCESS: User '{clients_hostname}' updated.")
            self.db_tools.update_client_entry( 
                db, 
                clients_hostname,
                clients_ip, 
                clients_last_seen, 
                clients_ddos_status,
                hashed_password
            )
            self.Crypto_utils.send_encrypted(client_sckt, aes_key, "SUCCESS: Logged in.")
            return True, clients_hostname, hashed_password

        return False, None, None
    
    
    def next_seq(self):
        global _seq_counter
        _seq_counter += 1
        return _seq_counter

    def now_iso(self):
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    def create_scan_message(self, ip_server, port_server):
        data = {
            "type": "command",
            "seq": self.next_seq(),     
            "timestamp": self.now_iso(), 
            "sender": {
                "ip": ip_server,
                "port": port_server
            },
            "body": {
                "action": "scan_arp",
                "params": {
                    "ip_victim": IP_VICTIM,  
                    "mac_sus": MAC_SUS,      
                    "duration_sec": 5        
                }
            }
        }
        return json.dumps(data)
    
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
        ip_server = client_sckt.getsockname()[0]
        port_server = client_sckt.getsockname()[1]
        
        print(f"[+] Connected by {addr}")

        client_pub_bytes = self.Crypto_utils.recv_framed(client_sckt)#Getting the content of .pem and creating .pem file 

        if not client_pub_bytes:
            print("ERROR: Did not receive client public key.")
            client_sckt.close()
            return
            
        client_pub = self.Crypto_utils.load_key_from_str(client_pub_bytes.decode())

        """The code above got the public key of the CLIENT - client_pub"""
        
        self.Crypto_utils.send_framed(client_sckt, self.public_key.export_key())

        encrypted_aes = self.Crypto_utils.recv_framed(client_sckt)
        if not encrypted_aes:
            print("ERROR: Did not receive encrypted AES key.")
            client_sckt.close()
            return        
        try:
            aes_key = self.Crypto_utils.rsa_decrypt(self.private_key, encrypted_aes)
            print("[*] Session AES key established")
        except ValueError as e:
            print(f"ERROR: RSA Decryption failed (Ciphertext length issue): {e}")
            client_sckt.close()
            return
        
        option_signing = self.Crypto_utils.recv_encrypted(client_sckt, aes_key)
        authenticated_hostname = None
        authenticated_password_hash = None
        if option_signing != "3":
            success, hostname, password_hash = self._authenticate_client(db,client_sckt, aes_key, addr, option_signing)
            
            if not success:
                return 
            authenticated_hostname = hostname
            authenticated_password_hash = password_hash
            if self.gui:
                self.gui.trigger_refresh()
        else:
            client_sckt.close()
            return
                
        while True:
            try:
                MENU = "Welcome for the arp detector and terminator project:\nFor scan : 1\nFor defense(POC) : 2\nFor exit: exit"
                self.Crypto_utils.send_encrypted(client_sckt, aes_key, MENU)
                
                client_choice = self.Crypto_utils.recv_encrypted(client_sckt, aes_key)
                
                if client_choice == "exit":
                    self.Crypto_utils.send_encrypted(client_sckt, aes_key, "GOODBYE")
                    try:
                        client_sckt.shutdown(socket.SHUT_RDWR)
                    except:
                        pass
                    client_sckt.close()
                    break
                
                if client_choice == "1":
                    command_scan_json = self.create_scan_message(ip_server, port_server)
                    command_dict = json.loads(command_scan_json) 
                    current_seq = command_dict.get("seq", "N/A")
                    self.Crypto_utils.send_encrypted(client_sckt, aes_key, command_scan_json)
                    print(f"Sent command to {addr}: scan_arp (Seq: {current_seq})")

                    response_from_client = self.Crypto_utils.recv_encrypted(client_sckt, aes_key)
                    print(f"[Client Response]: {response_from_client}")
                    
                elif client_choice == "2":
                    command_defense_json = self.create_defense_message(ip_server, port_server)
                    command_dict = json.loads(command_defense_json)
                    current_seq = command_dict.get("seq", "N/A")
                    self.Crypto_utils.send_encrypted(client_sckt, aes_key, command_defense_json)
                    print(f"Sent defense command to {addr}: run_defense_daemon (Seq: {current_seq})") # שימוש ב-current_seq                    
                    response_from_client = self.Crypto_utils.recv_encrypted(client_sckt, aes_key)
                    print(f"[Client Defense Response]: {response_from_client}")
                else:
                    self.Crypto_utils.send_encrypted(client_sckt, aes_key, "ERROR: Invalid option code.")
            except Exception as e:
                print("Error in handle_client:", e)
        if authenticated_hostname and authenticated_password_hash:
            clients_ip, _ = addr
            clients_last_seen = datetime.now()
            
            print(f"Updating last seen for {authenticated_hostname} before disconnect.")
            self.db_tools.update_client_entry( 
                db, 
                authenticated_hostname,
                clients_ip, 
                clients_last_seen, 
                'normal',  
                authenticated_password_hash 
            )
            
        if self.gui:
             self.gui.trigger_refresh()
        if db:
            try:
                db.close()
                print(f"[*] Closed DB connection for {addr}")
            except Exception as db_e:
                print(f"Warning: Could not close DB connection for {addr}: {db_e}")
        try:
            client_sckt.shutdown(socket.SHUT_RDWR)
        except:
            pass
        client_sckt.close()


    def start_server(self):
        s = socket.socket()

        self.gui = ServerGUI()
        gui_db = self.db_tools.initialize_database()
        threading.Thread(target=self.gui.run_gui, args=(gui_db,), daemon=True).start()

        s.bind((HOST, PORT))
        s.listen()
        print(f"[*] Server listening on {HOST}:{PORT}")
        while True:
            client_sckt, addr = s.accept()
            threading.Thread(target=self.handle_client, args=(client_sckt, addr)).start()

if __name__ == "__main__":
    my_server = Server()
    my_server.start_server()
