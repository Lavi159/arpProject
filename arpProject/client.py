import os
import socket
import json
import ipaddress
import re
from constants import HOST, PORT, KEYS_DIR
from crypto_utils import Crypto_utils,get_random_bytes

class Client:
    def __init__(self):
        print("client is running")
        self.Crypto_utils = Crypto_utils()
        self.priv_path, self.pub_path = self.Crypto_utils.generate_rsa_keys(KEYS_DIR, "client")
        self.private_key = self.Crypto_utils.load_key(self.priv_path) #Creating .pem file
        self.public_key = self.Crypto_utils.load_key(self.pub_path) #Creating .pem file
        
    def _validate_scan_arp_params(self, params):
        required_fields = ["ip_victim", "mac_sus", "duration_sec"]
        
        for field in required_fields:
            if field not in params:
                return False, f"Missing parameter for scan_arp: {field}"

        ip_v = self.normalize_ip(params["ip_victim"])
        mac_v = self.normalize_mac(params["mac_sus"])
        dur_v = self.validate_duration(params["duration_sec"])

        if ip_v is None:
            return False, "Invalid IP address for scan_arp"
        if mac_v is None:
            return False, "Invalid MAC address for scan_arp"
        if dur_v is None:
            return False, "Invalid duration_sec for scan_arp"

        params["ip_victim"] = ip_v
        params["mac_sus"] = mac_v
        params["duration_sec"] = dur_v

        return True, params
    
    def _validate_defense_params(self, params):
        required_fields = ["daemon_name", "mode"]
        
        for field in required_fields:
            if field not in params:
                return False, f"Missing parameter for defense: {field}"

        daemon_name = params["daemon_name"].lower()
        mode = params["mode"].upper()
        
        if daemon_name != "arpon":
            return False, f"Unsupported defense daemon: {daemon_name}"
        if mode != "SARPI":
            return False, f"Unsupported defense mode for {daemon_name}: {mode}"

        params["daemon_name"] = daemon_name
        params["mode"] = mode
        
        return True, params
    def check_valid_format(self, data):
        if "body" not in data or "action" not in data["body"] or "params" not in data["body"]:
            return False, "Missing keys in command"

        action = data["body"]["action"]
        params = data["body"]["params"]

        if action == "scan_arp":
            is_valid, validated_params = self._validate_scan_arp_params(params)
            
        elif action == "run_defense_daemon":
            is_valid, validated_params = self._validate_defense_params(params)
            
        else:
            return False, f"Unknown command action: {action}"

        if is_valid:
            return True, (action, validated_params)
        else:
            return False, validated_params
        
    def normalize_mac(self,mac):
        s = re.sub(r'[^0-9A-Fa-f]', '', mac).upper()
        if len(s) != 12:
            return None
        return ':'.join(s[i:i+2] for i in range(0, 12, 2))

    def normalize_ip(self,ip_str: str):
        if not isinstance(ip_str, str):
            return None
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            return str(ip_obj)   
        except Exception:
            return None
        
    def validate_duration(self,duration):
        try:
            d = int(duration)
            if d <= 0:
                return None
            return d
        except Exception:
            return None
    
    def _get_credentials_from_file(self, filename="credentials.txt", thread_id=None):

        try:
            with open(filename, 'r') as f:
                lines = f.readlines()
                
            if len(lines) < 3:
                print(f"[!] Credentials file '{filename}' is incomplete (expected 3 lines).")
                return None, None, None

            base_username = lines[0].strip()
            base_password = lines[1].strip()
            option_signing = lines[2].strip()

            if thread_id is not None:
                username = f"{base_username}_{thread_id}"
            else:
                username = base_username
            
            password = base_password
            
            if option_signing not in ["1", "2"]:
                 print(f"[!] Invalid option_signing in file: {option_signing}")
                 return None, None, None

            return option_signing, username, password

        except FileNotFoundError:
            print(f"[!] Credentials file '{filename}' not found.")
            return None, None, None
        except Exception as e:
            print(f"[!] Error reading credentials file: {e}")
            return None, None, None



        
    def connect_to_server(self,thread_id=None):
        s = socket.socket()
        try:
            s.connect((HOST, PORT))
            print(f"[{thread_id or 'Main'}] Connected to server")
        except ConnectionRefusedError:
            print(f"[{thread_id or 'Main'}] ERROR: Connection refused to {HOST}:{PORT}")
            return
        
        self.Crypto_utils.send_framed(s, self.public_key.export_key())
        server_pub_bytes = self.Crypto_utils.recv_framed(s)
        if not server_pub_bytes:
             print(f"[{thread_id or 'Main'}] ERROR: Server did not send public key.")
             s.close()
             return
        server_pub = self.Crypto_utils.load_key_from_str(server_pub_bytes.decode())
        aes_key = get_random_bytes(32)
        encrypted_aes = self.Crypto_utils.rsa_encrypt(server_pub, aes_key)
        self.Crypto_utils.send_framed(s, encrypted_aes)
        print(f"[{thread_id or 'Main'}] Session AES key sent")

        option_signing, username, password = self._get_credentials_from_file(thread_id=thread_id)
        
        if not username or not password or not option_signing:
            print(f"[{thread_id or 'Main'}] CRITICAL ERROR: Could not load valid credentials for automated run.")
            s.close()
            return
            
        if option_signing == "3":
             print(f"[{thread_id or 'Main'}] Quitting based on file option '3'.")
             s.close()
             return

        print(f"[{thread_id or 'Main'}] Using credentials from file: {username} (Option: {option_signing})")
        self.Crypto_utils.send_encrypted(s,aes_key,option_signing)
        self.Crypto_utils.send_encrypted(s,aes_key,username)
        self.Crypto_utils.send_encrypted(s,aes_key,password)
        
        auth_status_message = self.Crypto_utils.recv_encrypted(s, aes_key)
        print(f"[{thread_id or 'Main'}] Server Auth Status: {auth_status_message}")
        
        if "ERROR" in auth_status_message:
            s.close()
            return

        while True:
            
            recv_menu = self.Crypto_utils.recv_encrypted(s, aes_key)
            if recv_menu == "GOODBYE":
                print(f"[{thread_id or 'Main'}] Server sent GOODBYE, closing connection.")
                break
            print(f"[{thread_id or 'Main'}] Menu received: {recv_menu.splitlines()[0]}")
            
            option_code = "1" 
            print(f"[{thread_id or 'Main'}] Auto-selecting option: {option_code}")
            
            self.Crypto_utils.send_encrypted(s,aes_key,option_code)
            
            data_server = self.Crypto_utils.recv_encrypted(s, aes_key)
            
            if data_server is None:
                print(f"[{thread_id or 'Main'}] [!] Server disconnected. Received no data for JSON parsing.")
                break 

            try:
                data_server_dict = json.loads(data_server)
            except json.JSONDecodeError:
                print(f"[{thread_id or 'Main'}] ERROR: Received non-JSON data: {data_server}")
                break

            ok, result = self.check_valid_format(data_server_dict)
            if not ok:
                print(f"[{thread_id or 'Main'}] Invalid command received from server: {result}")
                break

            action, params = result
            print(f"[{thread_id or 'Main'}] Executing Action: {action}, Params: {params}")

            if action == "scan_arp":
                response_text = json.dumps({
                   "type": "response",
                   "status": "SUCCESS",
                   "message": f"Scan completed (Simulated) for {params['ip_victim']}.",
                   "seq": data_server_dict.get("seq", "N/A")
                })
                self.Crypto_utils.send_encrypted(s, aes_key, response_text)
            
            elif action == "run_defense_daemon":
                response_text = f"SUCCESS: {params.get('daemon_name')} started with code {params.get('mode')} (Simulated)."
                self.Crypto_utils.send_encrypted(s, aes_key, response_text)

            
            exit_code = "exit"
            print(f"[{thread_id or 'Main'}] Auto-selecting option: {exit_code}")
            
            self.Crypto_utils.send_encrypted(s, aes_key, exit_code)
            ack = self.Crypto_utils.recv_encrypted(s, aes_key)
            if ack:
                print(f"Server final message: {ack}")
            
        s.close()
        print(f"[{thread_id or 'Main'}] Connection closed.")

if __name__ == "__main__":
    my_client = Client()
    my_client.connect_to_server()
