from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256, MD5
import json
from base64 import b64encode, b64decode
from os.path import exists

class Encryptor:
    """Encryptor class
    """

    def __init__(self, path):
        self.path = path
        self.read_key_files()
    
    def read_key_files(self):
        """Read RSA key files
        """
        if not exists(self.path + '/public.pem') or not exists(self.path + '/private.pem'):
            self.generate_rsa_key()
        self.public_key = open(self.path + '/public.pem').read()
        self.private_key = open(self.path + '/private.pem').read()

    def xorcipher(self, data, key):
        """XOR cipher

        Args:
            data (bytes): Data to encrypt
            key (bytes): Key to encrypt data with
        
        Returns:
            bytes: Encrypted data
        """
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
    
    def encrypt_rsa(self, data, public_key):
        """Encrypts data with RSA

        Args:
            data (bytes): Data to encrypt
            public_key (bytes): Public key to encrypt data with

        Returns:
            bytes: Encrypted data
        """
        cipher = PKCS1_OAEP.new(RSA.importKey(public_key))
        return cipher.encrypt(data)

    def decrypt_rsa(self, data):
        """Decrypts data with RSA

        Args:
            data (bytes): Data to decrypt

        Returns:
            bytes: Decrypted data
        """
        cipher = PKCS1_OAEP.new(RSA.importKey(open(self.path + '/private.pem').read()))
        return cipher.decrypt(data)

    def generate_rsa_key(self):
        """Generates RSA key pair
        """
        random_generator = Random.new().read
        key = RSA.generate(1024, random_generator)
        private, public = key, key.publickey()
        open(self.path + '/private.pem', 'wb').write(private.exportKey('PEM'))
        open(self.path + '/public.pem', 'wb').write(public.exportKey('PEM'))
    
    def encrypt_passwords(self, passwords, key):
        """Encrypts passwords

        Args:
            passwords (dict): Passwords to encrypt
            key (bytes): Key to encrypt passwords with

        Returns:
            str: Encrypted passwords
        """
        return str(b64encode(self.xorcipher(json.dumps(passwords).encode(), key)))[2:]

    def decrypt_passwords(self, passwords, key):
        """Decrypts passwords

        Args:
            passwords (str): Passwords to decrypt
            key (bytes): Key to decrypt passwords with
        
        Returns:
            dict: Decrypted passwords
        """
        passwords = b64decode(passwords)
        return json.loads(self.xorcipher(passwords, key))

    def hash_string(self, string):
        """Hashes string

        Args:
            string (str): String to hash

        Returns:
            bytes: Hashed string
        """
        return SHA256.new(string.encode()).hexdigest()

    def generate_random_key(self):
        """Generates random key

        Returns:
            bytes: Random key
        """
        return Random.new().read(64)

    def generate_key_from_password(self, password):
        """Generates key from password
        
        Args:
            password (str): Password to generate key from

        Returns:
            bytes: Key
        """
        return MD5.new(password.encode()).digest()