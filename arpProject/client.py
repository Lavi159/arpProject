import os
import socket
import json
import ipaddress
import re
import threading
from constants import HOST, PORT, KEYS_DIR
import random
import subprocess
import time
from datetime import datetime
from crypto_utils import Crypto_utils
from Crypto.Random import get_random_bytes

class Client:
    def __init__(self):
        print("client is running")
        self.Crypto_utils = Crypto_utils()
        self.priv_path, self.pub_path = self.Crypto_utils.generate_rsa_keys(KEYS_DIR, "client")
        self.private_key = self.Crypto_utils.load_key(self.priv_path) #Creating .pem file
        self.public_key = self.Crypto_utils.load_key(self.pub_path) #Creating .pem file
    
    def command_listener(self, s, aes_key, baseline_ip, baseline_mac, iface):
        print("[*] Command listener started")

        while True:
            try:
                data = self.Crypto_utils.recv_encrypted(s, aes_key)
                if not data:
                    print("[!] Server disconnected (listener).")
                    break

                try:
                    msg = json.loads(data)
                except json.JSONDecodeError:
                    print("[!] Non-JSON command received:", data)
                    continue

                if msg.get("type") != "command":
                    continue

                body = msg.get("body", {})
                action = body.get("action")
                params = body.get("params", {})

                print(f"[CMD] Received command: {action}")

                if action == "run_defense_daemon":
                    # כאן מפעילים הגנה אמיתית
                    success, output = self.enforce_static_neighbor(
                        iface,
                        baseline_ip,
                        baseline_mac
                    )

                    response = {
                        "type": "response",
                        "status": "DEFENSE_APPLIED" if success else "DEFENSE_FAILED",
                        "timestamp": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
                        "message": output
                    }

                    self.Crypto_utils.send_encrypted(s, aes_key, json.dumps(response))

            except Exception as e:
                print("[!] Listener error:", e)
                break
        
    def monitor_loop(self, s, aes_key, baseline_ip, baseline_mac, iface, interval_sec=3):
        print(f"[*] Monitoring ARP for GW {baseline_ip} every {interval_sec}s on {iface}")

        last_status = None
        while True:
            arp = self.read_arp_cache()
            entry = arp.get(baseline_ip)

            observed_mac = entry["mac"] if entry else None

            if not observed_mac:
                self._run_cmd(["ping", "-c", "1", "-W", "1", baseline_ip])
                arp = self.read_arp_cache()
                entry = arp.get(baseline_ip)
                observed_mac = entry["mac"] if entry else None

            if not observed_mac:
                status = "ERROR"
                if status != last_status:
                    event = {
                        "type": "event",
                        "status": "ERROR",
                        "timestamp": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
                        "interface": iface or "",
                        "victim_ip": baseline_ip,
                        "expected_mac": baseline_mac,
                        "observed_mac": None,
                        "message": f"No ARP entry for gateway {baseline_ip}"
                    }
                    self.Crypto_utils.send_encrypted(s, aes_key, json.dumps(event))
                    last_status = status
                time.sleep(interval_sec)
                continue

            if observed_mac != baseline_mac:
                status = "SUSPECT"
                event = {
                    "type": "event",
                    "status": "SUSPECT",
                    "timestamp": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
                    "interface": iface or "",
                    "victim_ip": baseline_ip,
                    "expected_mac": baseline_mac,
                    "observed_mac": observed_mac,
                    "message": f"ARP spoofing suspected: expected {baseline_mac}, got {observed_mac}"
                }
                self.Crypto_utils.send_encrypted(s, aes_key, json.dumps(event))
                last_status = status
            else:
                status = "OK"
                if last_status != "OK":
                    event = {
                        "type": "event",
                        "status": "OK",
                        "timestamp": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
                        "interface": iface or "",
                        "victim_ip": baseline_ip,
                        "expected_mac": baseline_mac,
                        "observed_mac": observed_mac,
                        "message": f"Gateway mapping OK: {baseline_ip} -> {observed_mac}"
                    }
                    self.Crypto_utils.send_encrypted(s, aes_key, json.dumps(event))
                    last_status = status

            time.sleep(interval_sec)   
    
    def _run_cmd(self, cmd):
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = p.communicate()
        return p.returncode, out.strip(), err.strip()

    def get_default_route(self):
        # returns (gw_ip, iface) or (None, None)
        code, out, err = self._run_cmd(["ip", "route", "show", "default"])
        if code != 0 or not out:
            return None, None
        # example: "default via 192.168.1.1 dev eth0 proto dhcp metric 100"
        parts = out.split()
        if "via" not in parts or "dev" not in parts:
            return None, None
        gw = parts[parts.index("via") + 1]
        iface = parts[parts.index("dev") + 1]
        return self.normalize_ip(gw), iface

    def read_arp_cache(self):
        # returns dict ip->mac (normalized) from /proc/net/arp
        table = {}
        try:
            with open("/proc/net/arp", "r", encoding="utf-8") as f:
                lines = f.read().splitlines()
            # header: IP address HW type Flags HW address Mask Device
            for line in lines[1:]:
                cols = line.split()
                if len(cols) < 6:
                    continue
                ip = self.normalize_ip(cols[0])
                mac = self.normalize_mac(cols[3])
                flags = cols[2]
                dev = cols[5]
                if ip and mac and flags != "0x0":
                    table[ip] = {"mac": mac, "dev": dev}
        except Exception:
            pass
        return table

    def make_event(self, iface, victim_ip, old_mac, new_mac, action, method, status):
        return {
            "type": "event",
            "timestamp": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
            "interface": iface or "",
            "victim_ip": victim_ip,
            "old_mac": old_mac,
            "new_mac": new_mac,
            "action": action,          # blocked/allowed/ignored
            "method": method,          # arptables/arpon/manual
            "status": status,          # detected/enforced/failed
            "ddos_status": "normal"
        }

    def enforce_static_neighbor(self, iface, ip, mac):
        # defensive: lock mapping locally
        # requires root
        cmd = ["ip", "neigh", "replace", ip, "lladdr", mac, "nud", "permanent", "dev", iface]
        code, out, err = self._run_cmd(cmd)
        return code == 0, (out or err)
    
    def get_gateway_identity(self):
        gw_ip, iface = self.get_default_route()
        if not gw_ip:
            return None, None, None

        arp = self.read_arp_cache()
        entry = arp.get(gw_ip)

        if not entry:
            # ננסה לעורר ARP
            self._run_cmd(["ping", "-c", "1", "-W", "1", gw_ip])
            arp = self.read_arp_cache()
            entry = arp.get(gw_ip)

        if not entry:
            return gw_ip, iface, None

        return gw_ip, iface, entry["mac"]


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
    
    def _get_credentials_from_file(self, filename="arpProject/credentials/credentials", thread_id=None):
        try:
            num_file = random.randint(1,10)
            file_full_name = filename + str(num_file) + '.txt'
            with open(file_full_name, 'r') as f:
                lines = f.readlines()
                
            if len(lines) < 3:
                print(f"[!] Credentials file '{file_full_name}' is incomplete (expected 3 lines).")
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
            print(f"[!] Credentials file '{file_full_name}' not found.")
            return None, None, None
        except Exception as e:
            print(f"[!] Error reading credentials file: {e}")
            return None, None, None



        
    def connect_to_server(self, username=None, password=None, option_signing="1", thread_id=None, callback=None):
        s = socket.socket()
        try:
            s.connect((HOST, PORT))
            print(f"[{thread_id or 'Main'}] Connected to server")
        except Exception as e:
            error_msg = f"Connection refused to {HOST}:{PORT}"
            print(f"[{thread_id or 'Main'}] ERROR: {error_msg}")
            if callback: callback("Error", error_msg) 
            return
        
        try:
            self.Crypto_utils.send_framed(s, self.public_key.export_key())
            server_pub_bytes = self.Crypto_utils.recv_framed(s)
            if not server_pub_bytes:
                if callback: callback("Error", "Server did not send public key.")
                s.close()
                return
            
            server_pub = self.Crypto_utils.load_key_from_str(server_pub_bytes.decode())
            aes_key = get_random_bytes(32)
            encrypted_aes = self.Crypto_utils.rsa_encrypt(server_pub, aes_key)
            self.Crypto_utils.send_framed(s, encrypted_aes)
            print(f"[{thread_id or 'Main'}] Session AES key sent")

            if username is None or password is None:
                option_signing, username, password = self._get_credentials_from_file(thread_id=thread_id)

            if not username or not password or not option_signing:
                if callback: callback("Error", "Could not load valid credentials.")
                s.close()
                return

            self.Crypto_utils.send_encrypted(s, aes_key, option_signing)
            self.Crypto_utils.send_encrypted(s, aes_key, username)
            self.Crypto_utils.send_encrypted(s, aes_key, password)
            
            auth_status_message = self.Crypto_utils.recv_encrypted(s, aes_key)
            print(f"[{thread_id or 'Main'}] Server Auth Status: {auth_status_message}")
            
            if "ERROR" in auth_status_message:
                if callback: callback("Error", auth_status_message) 
                s.close()
                return
            else:
                if callback: callback("Success", auth_status_message) 

            gw_ip, iface, gw_mac = self.get_gateway_identity()
            if not gw_ip or not iface or not gw_mac:
                error_msg = "Could not determine gateway identity."
                if callback: callback("Error", error_msg)
                s.close()
                return

            client_info = {
                "type": "client_info",
                "gateway_ip": gw_ip,
                "gateway_mac": gw_mac,
                "interface": iface
            }

            self.Crypto_utils.send_encrypted(s, aes_key, json.dumps(client_info))
            
            threading.Thread(target=self.command_listener, 
                             args=(s, aes_key, gw_ip, gw_mac, iface), 
                             daemon=True).start()
            
            self.monitor_loop(s, aes_key, gw_ip, gw_mac, iface, 3)

        except Exception as e:
            print(f"[!] Error in communication: {e}")
            if callback: callback("Error", f"Communication error: {e}")
            s.close()

if __name__ == "__main__":
    from gui_client import ClientGUI
    app = ClientGUI()
    app.mainloop()
