"""
Author: Aleksa Vučković

Description: Implementation of private and public key rings.
"""
import json
import copy
import time
import os
from exceptions import DisplayableException
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA

_ID_MOD = 2**64

def drop_keys(dict, keys) -> dict:
    return {key: value for key, value in dict.items() if key not in keys}

class PrivateKeyData:

    def __init__(self, data: dict, ring):
        self._data = data
        self._ring = ring
    
    def __getattr__(self, name):
        if name in self._data:
            return self._data[name]
        return self.name
    def __getitem__(self, index):
        if isinstance(index, str): return self.__getattr__(index)
        raise Exception
    def __eq__(self, value) -> bool:
        return isinstance(value, PrivateKeyData) and self._data == value._data
    
    def delete(self):
        """
        Deletes this key from the ring.
        After calling this method, a PrivateKeyData object does not contain valid data,
        and should be deleted.
        """
        del self._ring._keys[self.key_id]
        self._ring._save()
    
    def decode(self, password: str) -> RSA.RsaKey:
        """
        Raises: DisplayableException if the password is incorrect.
        Returns: The RSA.RsaKey object.
        """
        try: return RSA.import_key(self.private_pem, password)
        except Exception as e: raise DisplayableException("Incorrect password.") from e
    
    def export(self, filepath, password = None, export_pass = None):
        """
        Exports key to file.
        Args:
            password: If None, key is exported as a public key. Otherwise, this password must match the private key.
            export_pass: When exporting as private key, the password used to encrypt the exported file (in pkcs#8 format). If None, the file is not encrypted.
        Raises: DisplayableException if password is incorrect (and not None).
        """
        if password is None: output = self.public.export_key("PEM")
        else: output = self.decode(password).export_key("PEM", passphrase=export_pass, pkcs=8)
        with open(filepath, "w") as file:
            file.write(output.decode())

class PrivateKeyRing:
    """
    Private keys are stored in a json file.
    A single object has the following format:
        {
            timestamp: epoch seconds time when the key was added to this ring
            key_id: last 64 bits of key modulus, as a hex string
            public_pem: public key as a pem format string
            public: public key as an RSA.RsaKey object, not stored in the json file
            private_pem: private key as an encrypted PEM format string (pkcs#8)
            name: name
            email: email
		}
    The 'private' key can only be converted into an RsaKey object using the appopriate password.

    Use get_instance to get a user's instance, ensuring that only one instance per user is created.
    """
    _instance = None
    @staticmethod
    def get_instance():
        if PrivateKeyRing._instance is None:
            PrivateKeyRing._instance = PrivateKeyRing()
        return PrivateKeyRing._instance
    
    def _get_file_path(self):
        path = f"data/private.json"
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return path

    def __init__(self):
        try:
            with open(self._get_file_path(), "r") as file:
                data = file.read()
        except FileNotFoundError: data = "{}"
        self._keys = json.loads(data)
        for key in self._keys.values():
            key["public"] = RSA.import_key(key["public_pem"])
    def _save(self):
        keys = {id: drop_keys(key, ["public"]) for id, key in self._keys.items()}
        with open(self._get_file_path(), 'w') as file:
            json.dump(keys, file)

    def generate_key(self, password:str, size:int, name: str, email: str) -> PrivateKeyData:
        """
        Generates a new key, adds it to the ring.
        Returns: The generated PrivateKeyData object.
        """
        if size <= 2048: size = 2048
        else: size = 4092
        private = RSA.generate(bits=size, e=65537)
        public = private.public_key()
        key_id = hex(private.n % _ID_MOD)
        data = {
            "timestamp": time.time(),
            "key_id": key_id,
            "public": public,
            "public_pem": public.export_key("PEM").decode(),
            "private_pem": private.export_key("PEM", passphrase=password, pkcs=8).decode(),
            "name": name,
            "email": email
        }
        # if key_id in self._keys ??
        self._keys[key_id] = data
        self._save()
        return PrivateKeyData(data, self)
    def get_all(self):
        """Returns: All keys as a dictionary of PrivateKeyData objects."""
        res = dict()
        for key_id, data in self._keys.items(): res[key_id] = PrivateKeyData(data, self)
        return res
    def get_key(self, key_id):
        """Returns the key object. Raises exception if it doesn't exist."""
        return PrivateKeyData(self._keys[key_id], self)
    def import_key(self, filepath_or_string: str, password:str, name: str, email: str, import_pass: str = None):
        """
        Imports key in pem format. Accepts a filepath or a string containing the private key.
        Uses password to encrypt the key, and import_pass do decrypt the key file.
        Raises:
            FileNotFoundError:  If file doesn't exist or can't be read.
            DisplayableException: If password is incorrect, or the key is public, or there is a key id conflict.
        Returns: The imported PrivateKetData object.
        """
        if "-----BEGIN" in filepath_or_string: data = filepath_or_string
        else:
            with open(filepath_or_string, "r") as file:
                data = file.read()
        try: private = RSA.import_key(data, import_pass)
        except ValueError as v: raise DisplayableException("Couldn't read the key. Please check the format and password.") from v
        if not private.has_private(): raise DisplayableException("Only public key info was found in the file.")
        public = private.public_key()
        key_id = hex(private.n % _ID_MOD)
        key = {
            "timestamp": time.time(),
            "key_id": key_id,
            "public": public,
            "public_pem": public.export_key("PEM").decode(),
            "private_pem": private.export_key("PEM", passphrase=password, pkcs=8).decode(),
            "name": name,
            "email": email
        }
        if key_id in self._keys: raise DisplayableException("Key ID conflict!")
        self._keys[key_id] = key
        self._save()
        return PrivateKeyData(key, self)
    
class PublicKeyData:
    def __init__(self, data: dict, ring):
        self._data = data
        self._ring = ring
    
    def __getattr__(self, name):
        if name in self._data:
            return self._data[name]
        return super().__getattr__(name)
    def __getitem__(self, index):
        if isinstance(index, str): return self.__getattr__(index)
        raise Exception
    def __eq__(self, value) -> bool:
        return isinstance(value, PrivateKeyData) and self._data == value._data
    
    def delete(self):
        """
        Deletes key.
        The PublicKeyData object is not valid after this method is called,
        and should be deleted.
        """
        del self._ring._keys[self.key_id]
        self._ring._save()
    def export(self, filepath):
        """Exports key to file in pem format."""
        with open(filepath, "w") as file:
            file.write(self.public_pem)
    def add_signature(self, email):
        """
        Adds email to key signatures.
        """
        self.signatures.append(email)
        self._ring._update_trust_score(self._data)
        self._ring._save()
    def sign(self):
        """Marks the key as valid."""
        self.add_signature(PublicKeyRing._SELF_SIGN)

class PublicKeyRing:
    """
    Public keys are stored in a json file.
    A single object has the following format:
        {
            timestamp: epoch seconds time when the key was added to this ring
            key_id: last 64 bits of key modulus, as a hex string
            public_pem: public key as a pem format string
            public: public key as an rsa.PublicKey object, not stored in the json file
            owner_trust: number from 0 to 100 indicating how much the owner of this key is trusted when signing other keys
            name: owner's name
            email: owner's email
            legitimacy: True or False, calculated based on the signatures
            trust_score: sum of trust values for each signature
            signatures: a list of emails,
		}
    The 'public_pem' field is converted into an RsaKey object when loaded from the file, and stored in the 'public' attribute.
    For simplicity, the owner_trust value is stored redundantly in each entry of an owner.
    
    Use get_instance to obtain ring, ensuring that only one instance is created.
    """
    _SELF_SIGN = "*"
    _instance = None
    @staticmethod
    def get_instance():
        if PublicKeyRing._instance is None: PublicKeyRing._instance = PublicKeyRing()
        return PublicKeyRing._instance
    
    def _get_file_path(self):
        path = f"data/public.json"
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return path

    def __init__(self):
        try:
            with open(self._get_file_path(), "r") as file:
                data = file.read()
        except FileNotFoundError: data = "{}"
        self._keys = json.loads(data)
        for key in self._keys.values():
            key["public"] = RSA.import_key(key["public_pem"])
    def _save(self):
        keys = {id: drop_keys(key, ["public"]) for id, key in self._keys.items()}
        with open(self._get_file_path(), 'w') as file:
            json.dump(keys, file)
    
    def get_owner_trust(self, email: str) -> int:
        if email == PublicKeyRing._SELF_SIGN: return 100
        for key in self._keys.values():
            if key["email"] == email: return key["owner_trust"]
        return 0
    def _update_trust_score(self, key):
        res = 0
        for email in key["signatures"]:
            res += self.get_owner_trust(email)
        key["trust_score"] = res
        key["legitimacy"] = res >= 100
    def set_owner_trust(self, email: str, owner_trust: int):
        if owner_trust is None: return
        if owner_trust > 100: owner_trust = 100
        if owner_trust < 0: owner_trust = 0
        #updating all entries for the user
        for key in self._keys.values():
            if key["email"] == email:
                key["owner_trust"] = owner_trust
        #updating all dependent trust scores
        for key in self._keys.values():
            if email in key["signatures"]: self._update_trust_score(key)
        self._save()

    def add_key(self, value: str, name, email, owner_trust = None, signatures = []) -> PublicKeyData:
        """
        Adds new public key.
        If owner_trust is None, than the existing owner_trust value is used, or 0 if no entries exists.
        Args:
            value(str): The file path or string containing the public key in pem format.
        Raises:
            FileNotFoundError: If the file can't be read or doesn't contain a valid public key.
            DisplayableError: If the key format is incorrect, or there is a key_id conflict.
        Returns: The key object.
        """
        if "-----BEGIN" in value: data = value
        else:
            with open(value, "r") as file:
                data = file.read()
        try: public = RSA.import_key(data)
        except ValueError as e: raise DisplayableException("Couldn't load the key. Check the file path or contents.") from e
        if owner_trust is None: owner_trust = self.get_owner_trust(email)
        else: self.set_owner_trust(email, owner_trust)
        key_id = hex(public.n % _ID_MOD)
        key = {
            "timestamp": time.time(),
            "key_id": key_id,
            "public_pem": data,
            "public": public,
            "owner_trust": owner_trust,
            "name": name,
            "email": email,
            "legitimacy": False,
            "trust_score": 0,
            "signatures": signatures
        }
        if key_id in self._keys: raise DisplayableException("There is a key ID conflict!")
        self._keys[key_id] = key
        self._update_trust_score(key)
        self._save()
        return PublicKeyData(key, self)
    def get_all(self):
        """Returns: All keys as a dictionary of PublicKeyData objects."""
        res = {}
        for key_id, key in self._keys.items(): res[key_id] = key
        return res
    def get_keys(self, email):
        """Returns: A dictionary of PublicKeyData objects associated with this email."""
        res = {}
        for key in self._keys.values():
            if key["email"] == email: res[key["key_id"]] = PublicKeyData(key, self)
        return res
    def get_key(self, key_id) -> PublicKeyData:
        """Returns: A PublicKeyData object."""
        return PublicKeyData(self._keys[key_id], self)