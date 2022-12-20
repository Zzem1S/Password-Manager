import requests
from base64 import b64encode, b64decode
import json

from lib.encryptor import Encryptor

class Client:
    """Client class for interacting with the server
    """

    def __init__(self, url):
        self.url = url
        self.encryptor = Encryptor("client")
        self.server_key = self.get_public_key()
        self.key = self.encryptor.generate_random_key()
        
    def get_passwords(self, username, master_password):
        """Get passwords from the server

        Args:
            username (str): Username
            master_password (str): Master password

        Returns:
            str: Passwords
        """
        request = {"username": username, "master_password": master_password}
        request = self.encrypt_request(request, self.server_key)
        url = self.url + f"/?type=getpasswords&request={request}&public_key={b64encode(self.encryptor.public_key.encode('utf-8')).decode('utf-8')}"
        response = requests.get(url)
        return self.decrypt_response(response.content)

    def add_password(self, username, master_password, password_name, password):
        """Add password to the server

        Args:
            username (str): Username
            master_password (str): Master password
            password_name (str): Password name
            password (str): Password

        Returns:
            str: Passwords
        """
        request = {"username": username, "master_password": master_password, "password_name": password_name, "password": password}
        request = self.encrypt_request(request, self.server_key)
        url = self.url + f"/?type=addpassword&request={request}&public_key={b64encode(self.encryptor.public_key.encode('utf-8')).decode('utf-8')}"
        response = requests.get(url)
        return self.decrypt_response(response.content)

    def get_public_key(self):
        """Get public key from the server

        Returns:
            bytes: Public key
        """
        url = self.url + f"/?type=getpublickey&public_key={b64encode(self.encryptor.public_key.encode('utf-8')).decode('utf-8')}"
        response = requests.get(url)
        return b64decode(response.content + b"==")

    def encrypt_request(self, request, public_key):
        """Encrypt request

        Args:
            request (dict): Request
            public_key (str): Public key

        Returns:
            str: Encrypted request
        """
        enc_request = b64encode(b64encode(self.encryptor.encrypt_rsa(self.key, public_key)) + b" " + \
        b64encode(self.encryptor.xorcipher(bytes(json.dumps(request), "utf-8"), self.key))).decode("utf-8")
        return enc_request
    
    def decrypt_response(self, response):
        """Decrypt response

        Args:
            response (str): Encrypted response

        Returns:
            str: Decrypted response
        """
        enc_key, enc_response = b64decode(response + b"==").split(b" ")
        key = self.encryptor.decrypt_rsa(b64decode(enc_key + b"=="))
        return self.encryptor.xorcipher(b64decode(enc_response + b"=="), key).decode("utf-8")
    
    