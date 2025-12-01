import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64
import json

class Crypto_utils:
    def __init__(self):
        pass
    # === RSA ===

    def generate_rsa_keys(self,path: str, name: str):
        os.makedirs(path, exist_ok=True)
        priv_path = os.path.join(path, f"{name}_private.pem")
        pub_path = os.path.join(path, f"{name}_public.pem")
        if not os.path.exists(priv_path):
            key = RSA.generate(2048)
            with open(priv_path, "wb") as f:
                f.write(key.export_key())
            with open(pub_path, "wb") as f:
                f.write(key.publickey().export_key())
        return priv_path, pub_path


    def send_framed(self, sock, ciphertext):
        length = len(ciphertext).to_bytes(4, 'big')
        sock.sendall(length + ciphertext)
    
    def recv_framed(self, sock):
        length_data = sock.recv(4)
        if not length_data:
            return None
        length = int.from_bytes(length_data, 'big')
        data = b''
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def load_key(self,path):
        with open(path, "rb") as f:
            return RSA.import_key(f.read())

    def load_key_from_str(self,key_str: str):
        """Creating .pem file"""
        return RSA.import_key(key_str.encode())

    def rsa_encrypt(self,public_key, data: bytes) -> bytes:
        return PKCS1_OAEP.new(public_key).encrypt(data)


    def rsa_decrypt(self,private_key, data: bytes) -> bytes:
        return PKCS1_OAEP.new(private_key).decrypt(data)


    # === AES ===

    def aes_encrypt(self,key: bytes, data: bytes):
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce, ciphertext, tag


    def aes_decrypt(self,key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes):
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    def send_encrypted(self, sock, aes_key, text: str):
        nonce, ct, tag = self.aes_encrypt(aes_key, text.encode('utf-8'))

        frame = json.dumps({
            "nonce": self.b64e(nonce),
            "ciphertext": self.b64e(ct),
            "tag": self.b64e(tag)
        }).encode('utf-8')

        self.send_framed(sock, frame)

    def recv_encrypted(self,sock, aes_key):
        data = self.recv_framed(sock)
        if not data:
            return None

        msg = json.loads(data.decode('utf-8'))

        nonce = self.b64d(msg["nonce"])
        ct    = self.b64d(msg["ciphertext"])
        tag   = self.b64d(msg["tag"])

        plain = self.aes_decrypt(aes_key, nonce, ct, tag)
        return plain.decode('utf-8')

    def b64e(self,b: bytes) -> str:
        return base64.b64encode(b).decode()

    def b64d(self,s: str) -> bytes:
        return base64.b64decode(s.encode())
