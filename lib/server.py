from http.server import HTTPServer, BaseHTTPRequestHandler
from base64 import b64decode, b64encode
import json

from lib.database import Db
from lib.encryptor import Encryptor

class Handler(BaseHTTPRequestHandler):
    """ Password manager request handler
    """

    def do_GET(self):
        """Handles GET requests
        """
        self.db = Db()
        self.encryptor = Encryptor("server")
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        data = {x.split("=")[0] : x.split("=")[1] for x in self.path.split("/")[-1].split("?")[-1].split("&")}
        resp = b""
        
        self.random_key = self.encryptor.generate_random_key()
        self.client_public_key = b64decode(data["public_key"] + "==")

        if data["type"] == "getpublickey":
            resp = self.get_public_key()
            self.wfile.write(resp)
            return 
    
        elif data["type"] == "getpasswords":
            data = self.decrypt_request(data["request"])
            self.username = data["username"]
            self.master_password = data["master_password"]
            self.key = self.encryptor.generate_key_from_password(self.master_password)

            if not self.check_if_user_exists():
                self.register_user()
            if self.check_master_password():
                resp = bytes(json.dumps(self.get_passwords()), "utf-8")
            else:
                resp = b"Bad master password or username"
        elif data["type"] == "addpassword":
            data = self.decrypt_request(data["request"])
            self.username = data["username"]
            self.master_password = data["master_password"]
            self.key = self.encryptor.generate_key_from_password(self.master_password)
            if not self.check_if_user_exists():
                self.register_user()
            if self.check_master_password():
                self.add_password(data["password_name"], data["password"])
                resp = b"Password added"
            else:
                resp = b"Bad master password or username"

        resp = self.encrypt_response(resp, self.client_public_key)
        
        self.wfile.write(resp)


    def encrypt_response(self, response, public_key):
        """Encrypts response

        Args:
            response (dict): Response to encrypt
            public_key (str):  Public key to encrypt response with

        Returns:
            bytes: Encrypted response
        """
        return b64encode(b64encode(self.encryptor.encrypt_rsa(self.random_key, public_key)) + b" " + \
        b64encode(self.encryptor.xorcipher(response, self.random_key)))

    def decrypt_request(self, request):
        """Decrypts request

        Args:
            request (str): Request to decrypt

        Returns:
            dict: Decrypted request
        """
        enc_key, enc_request = b64decode(request + "==").split(b" ")
        key = self.encryptor.decrypt_rsa(b64decode(enc_key + b"=="))
        return json.loads(self.encryptor.xorcipher(b64decode(enc_request + b"=="), key).decode("utf-8"))

    def get_public_key(self):
        """Returns public key

        Returns:
            bytes: Public key
        """
        return b64encode(self.encryptor.public_key.encode('utf-8'))

    def check_master_password(self):
        """Checks if master password is correct

        Returns:
            Bool: True if master password is correct, False otherwise
        """
        master_password_hash = self.db.get_master_password(self.username)
        if self.encryptor.hash_string(self.master_password) == master_password_hash:
            return True
        return False

    def register_user(self):
        """Registers user
        """
        self.db.write("master_passwords", "username, password", self.username, self.encryptor.hash_string(self.master_password))
        self.db.write("passwords", "username, passwords", self.username, self.encryptor.encrypt_passwords({}, self.key))

    def check_if_user_exists(self):
        """Checks if user exists

        Returns:
            Bool: True if user exists, False otherwise
        """
        return self.db.check_if_user_exists(self.username)

    def get_passwords(self):
        """Returns passwords

        Returns:
            dict: Passwords
        """
        return self.encryptor.decrypt_passwords(self.db.get_passwords(self.username), self.key)

    def add_password(self, password_name, password):
        current_passwords = self.get_passwords()
        current_passwords[password_name] = password
        self.db.remove("passwords", "username", self.username)
        self.db.write("passwords", "username, passwords", self.username, self.encryptor.encrypt_passwords(current_passwords, self.key))
    


class Server():
    """ Password manager server
    """

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server = HTTPServer((self.host, self.port), Handler)

    def start(self):
        """Starts the server
        """
        print("Starting server...")
        self.server.serve_forever()

    def stop(self):
        """Stops the server
        """
        self.server.server_close()
