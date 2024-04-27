"""
Author: Aleksa Vučković

Description: Implementation of private and public key rings.
"""
import json
import copy
import time
import rsa
import os
import base64
from exceptions import DisplayableException
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256

_ID_MOD = 2**64

class PrivateKeyData:
    @staticmethod
    def _encode_private_key(private: rsa.PrivateKey, password: bytes) -> str:
        """
        Returns the encrypted pkcs1 pem string for this private key.
        Encryption is done using AES in CCM mode.
        """
        pem = private._save_pkcs1_pem()
        password = SHA256.new(password).digest()
        aes = AES.new(key = password, mode = AES.MODE_CCM, nonce = b'00000000', mac_len=16)
        encoded, tag = aes.encrypt_and_digest(pem)
        return base64.b64encode(encoded + tag).decode()
    @staticmethod
    def _decode_private_key(encoded: str, password: bytes) -> rsa.PrivateKey:
        """
        Decode private key encoded using _encode_private_key.
        Raises an exception if the password is incorrect.
        """
        encoded = base64.b64decode(encoded.encode())
        encoded, tag = encoded[:-16], encoded[-16:]
        password = SHA256.new(password).digest()
        aes = AES.new(key = password, mode = AES.MODE_CCM, nonce = b'00000000', mac_len=16)
        try: pem = aes.decrypt_and_verify(encoded, tag)
        except ValueError as v: raise DisplayableException("Incorrect password.") from v
        return rsa.PrivateKey._load_pkcs1_pem(pem)

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
        Deletes this key from the ring.
        After calling this method, a PrivateKeyData object does not contain valid data,
        and should be deleted.
        """
        del self._ring._keys[self.key_id]
        self._ring._save()
    
    def decode(self, password: str) -> rsa.PrivateKey:
        """
        Raises: DisplayableException if the password is incorrect.
        Returns: The rsa.PrivateKey object.
        """
        try: return PrivateKeyData._decode_private_key(self.private_pem, password.encode())
        except ValueError as v: raise DisplayableException("Incorrect password.") from v
    
    def export(self, filepath, password = None):
        """
        Exports key to file.
        If password is None, exports as public key.
        Otherwise, the password must match the private key.
        Raises: DisplayableException if password is incorrect (and not None).
        """
        if password is None: output = self.public.save_pkcs1()
        else: output = self.decode(password).save_pkcs1()
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
            public: public key as an rsa.PublicKey object, not stored in the json file
            private_pem: private key as a pem format string - encrypted using the SHA 512 hash of the password
		}
    The 'private' key can only be converted into an PrivateKey object using the appopriate password,
    so to get the private key object use get_private_key.

    Each user has their own private key ring.
    Use get_instance to get a user's instance, ensuring that only one instance per user is created.
    """
    _instances = dict()
    @staticmethod
    def get_instance(username):
        instances = PrivateKeyRing._instances
        if username not in instances: instances[username] = PrivateKeyRing(username)
        return instances[username]
    
    def _get_file_path(self):
        path = f"data/{self.username}/private.json"
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return path

    def __init__(self, username):
        self.username = username
        try:
            with open(self._get_file_path(), "r") as file:
                data = file.read()
        except FileNotFoundError: data = "{}"
        self._keys = json.loads(data)
        for key in self._keys.values():
            key["public"] = rsa.PublicKey._load_pkcs1_pem(key["public_pem"])
    def _save(self):
        ring = copy.deepcopy(self._keys)
        for key in ring.values():
            del key["public"]
        with open(self._get_file_path(), 'w') as file:
            json.dump(ring, file)

    def generate_key(self, password:str, size:int) -> PrivateKeyData:
        """
        Generates a new key, adds it to the ring.
        Returns: The generated PrivateKeyData object.
        """
        if size <= 2048: size = 2048
        else: size = 4092
        public, private = rsa.newkeys(exponent=65537,nbits=size)
        key_id = hex(private.n % _ID_MOD)
        data = {
            "timestamp": time.time(),
            "key_id": key_id,
            "public": public,
            "public_pem": public._save_pkcs1_pem().decode(),
            "private_pem": PrivateKeyData._encode_private_key(private, password.encode())
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
    def import_key(self, filepath_or_string: str, password:str):
        """
        Imports key in pem format. Accepts a filepath or a string containing the private key.
        Uses password to encrypt the key.
        Raises:
            FileNotFoundError:  If file doesn't exist or can't be read.
            DisplayableException: If password is incorrect.
        Returns: The imported PrivateKetData object.
        """
        if "-----BEGIN" in filepath_or_string: data = filepath_or_string
        else:
            with open(filepath_or_string, "r") as file:
                data = file.read()
        try: private = rsa.PrivateKey._load_pkcs1_pem(data)
        except ValueError as v: raise DisplayableException("Couldn't read the key. Please check the format - only PKCS#1 is accepted.") from v
        public = rsa.PublicKey(private.n, private.e)
        key_id = hex(private.n % _ID_MOD)
        key = {
            "timestamp": time.time(),
            "key_id": key_id,
            "public": public,
            "public_pem": public._save_pkcs1_pem().decode(),
            "private_pem": PrivateKeyData._encode_private_key(private, password.encode())
        }
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
    The 'public_pem' field is converted into a PublicKey object when loaded from the file, and stored in the 'public' attribute.
    For simplicity, the owner_trust value is stored redundantly in each entry of an owner.
    
    Each user has their own public key ring.
    Use get_instance to get a user's instance, ensuring that only one instance per user is created.
    """
    _instances = dict()
    @staticmethod
    def get_instance(username: str):
        instances = PublicKeyRing._instances
        if username not in instances: instances[username] = PublicKeyRing(username)
        return instances[username]
    
    def _get_file_path(self):
        path = f"data/{self.username}/public.json"
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return path

    def __init__(self, username):
        self.username = username
        try:
            with open(self._get_file_path(), "r") as file:
                data = file.read()
        except FileNotFoundError: data = "{}"
        self._keys = json.loads(data)
        for key in self._keys.values():
            key["public"] = rsa.PublicKey._load_pkcs1_pem(key["public_pem"])
    def _save(self):
        keys = copy.deepcopy(self._keys)
        for key in keys.values():
            del key["public"]
        with open(self._get_file_path(), 'w') as file:
            json.dump(keys, file)
    
    def get_owner_trust(self, email: str) -> int:
        if email == self.username: return 100
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
            value(str): The file path or string containing the pem public key in PKCS#1 format.
        Raises:
            FileNotFoundError: If the file can't be read or doesn't contain a valid public key.
            DisplayableError: If the key format is incorrect.
        Returns: The key object.
        """
        if "-----BEGIN" in value: data = value
        else:
            with open(value, "r") as file:
                data = file.read()
        try: public = rsa.PublicKey.load_pkcs1(data.encode())
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