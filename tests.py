import unittest
import shutil
from keys import PrivateKeyRing, PublicKeyRing
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
import os
from exceptions import *


private_pem = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCCXpHNE7/snIil
HbknKVTzBgKSiwBkuSzANYNGxNqwBzjmoXkW8B2K7BEJh1tz8ibkX/tUCtNGJ92z
hvj6PUgwgDdrOArbcqfz4YW9SChCl0HnXBD0PpEujRex0vF1ufAerZ1Q/OdOK+8+
CMN1XzEGXcEsMIhh1WyqDxmnA69Ty9A5pnmDwXM+wjWT+t282PYQ8vD6lvPH26rl
PxcfnMnu/vzlM/ImNdMQYQE8vZxnoOIhbM1wjzDY/rVFBpbVuac51PomPMmJYUAK
iCFIdovgPGdZsCMEN8bXD6/pGtGuNi84vudl5VknEnF31uOTn4bVepd3crkVoElh
zFhDMnotAgMBAAECggEAHdd65WgLayRrrOwQWVP/M3/hL90skmHGyhqVuanO6zNE
BZrZpnQBNy8ROU6oEvLPj0AfPh4aPXlbqMARFurXLu7ygJL7/T6SDmPFos21FYUd
G1H6OYZm4jJ+xYAlME8HFWalV4gEhGLPKTKFV0UaajwkvzI+zbI2ZPj+5LmVtQbj
OL1bZPvBWNUi2ka9q5Po2tGv2M3aNFl0bhxr3AoytY8pgd02pBa2T9N48McEP78x
nTn8TXCoJ7bYvx5mhYekZgL39WOxcMR+UOOnPm+W0o+JMweJ7ltC9xeYmHsAeYm5
o0uXZVG0oT89bQSjQ56KosTlKKAKNoZNNe6EXui+qwKBgQC2zxGscwGAt36BdBD5
nrxlA60Dk3VcgaJWGBguQOgVf8fD9nQvIO0O4cAE/HgDFMy2T5OSGehj2I8xETrn
qR5AK7+pfFIPGdZjroIiaenKTpHQwbZtghPs13aT0gO5GS7iYTSCSdlAuRaZnm5u
ffsss6McLK6IsGN0X/x13brwvwKBgQC2kLy2tFuIES8LFtVfEuGo1iTjAqzH9zo/
fHIfvAU2irWlos5lGTXIhBgGpdw9SahIT5/IODMokOHGiM+OPXS1gACvHuc1DoDv
ouc71RcUjaiUJMqaFAZtE0XfRyS7UBu3I6V7eYcBtVw0vxnvySbRYHg3u0Wyolal
t1HSAbhkEwKBgDlbwUzdjOQpLt1JYKYh4zTCsX+Evfc3iYr/5l5k6S0Nuc1Hv+6l
oxvfQ1ONL86vsQem8kOOM3dYlJ0trdDQJHi4AVwZcNniHn2KXLSVjNB4VJIupaG4
ha3zcPYymA5001weac5Tg4ImUOwEZNvwVWYSOyR09JJY3eu+zkThPG2bAoGAbF8Y
lsATQX8p1MRWHpy/tZCAzvzMgdtBCWSe/jWHRqwqTcuKBzti0MeQ14lnZj4uFdam
O50YyTDPxSF7S60xdXgpb8rBZp5YbWffKYZBsCKy+lWoqrPOaLszE+pQZJyWBy2y
0sv+F0aIGIuEIvHeCBXi5vpU0khJdQ+QE0CQK18CgYEAiNYsMF5CRoHQjFIfEv3t
DP6fR9G5lMSrKtkiLt3ZQmHe027dNb5K1FiiNl/VfOEuIqoY2fIwLGsVxaq+tysf
rGqCTRN0GRb1lvK3z4BRqazrqNng+SzNWwclqphdtt6PlTYCHPpJI7LJgrweoe9Z
dYX71JNHCdoSsu8cLvuNBHA=
-----END PRIVATE KEY-----"""
public_pem = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgl6RzRO/7JyIpR25JylU
8wYCkosAZLkswDWDRsTasAc45qF5FvAdiuwRCYdbc/Im5F/7VArTRifds4b4+j1I
MIA3azgK23Kn8+GFvUgoQpdB51wQ9D6RLo0XsdLxdbnwHq2dUPznTivvPgjDdV8x
Bl3BLDCIYdVsqg8ZpwOvU8vQOaZ5g8FzPsI1k/rdvNj2EPLw+pbzx9uq5T8XH5zJ
7v785TPyJjXTEGEBPL2cZ6DiIWzNcI8w2P61RQaW1bmnOdT6JjzJiWFACoghSHaL
4DxnWbAjBDfG1w+v6RrRrjYvOL7nZeVZJxJxd9bjk5+G1XqXd3K5FaBJYcxYQzJ6
LQIDAQAB
-----END PUBLIC KEY-----"""
public_pem2 = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvODYgeN+3vFWFP+B2xYN
K8QpPB6+hHqacLhJPqoQ5aPRH75Uc4o9VynbgytLrn7l9XBKcPRGAZaF2g975dhK
hNWfo0+yemOKXrGhPS4uZbiplOvEkMSYbIjKKVTGxDKjNsQGPvzNW8i7TxUEP3EK
XTNKrxBRiiGkj69YZUiHFrUAzRdXeJ7PvyHPpsrKQokWrEuQxxHa+NoZ8Pn1kFSI
y9ZU+ptZ/dfXbXzAob0HwdIsYARAFxpFAk2dBPApPZfwXng0w3N8AT+Kam8tKJnZ
5XzIQxq/ylYLhRUHtu/8v+amNETSe8nh4SeNrPXz9Caj065LiwfQjkEihgPHsIPW
MQIDAQAB
-----END PUBLIC KEY-----"""


username = "aleksa"
password = "mypass"
testfiles = ["test.txt"]
class KeysTest(unittest.TestCase):
    def _reset_files(self, username):
        shutil.rmtree(f"data/{username}", ignore_errors=True)

    def setUp(self) -> None:
        self._reset_files(username)
        PublicKeyRing._instances = dict()
        PrivateKeyRing._instances = dict()
    def tearDown(self) -> None:
        self._reset_files(username)
        PublicKeyRing._instances = dict()
        PrivateKeyRing._instances = dict()
        for file in testfiles:
            if os.path.exists(file):
                os.unlink(file)

    def test_private_key_encryption(self):
        ring: PrivateKeyRing = PrivateKeyRing.get_instance(username)
        key = ring.generate_key(password, 2048)
        private = key.decode(password)
        public = key.public

        msg = b"Hello"
        enc = PKCS1_OAEP.new(public).encrypt(msg)
        dec = PKCS1_OAEP.new(private).decrypt(enc)
        self.assertTrue(msg == dec)

        with self.assertRaises(DisplayableException):
            key.decode("badpass")
    
    def test_private_key_import_export(self):
        ring: PrivateKeyRing = PrivateKeyRing.get_instance(username)
        key = ring.import_key(private_pem, password)
        private = key.decode(password)
        public = key.public
        msg = b"Hello"
        enc = PKCS1_OAEP.new(public).encrypt(msg)
        dec = PKCS1_OAEP.new(private).decrypt(enc)
        self.assertTrue(msg == dec)

        filepath = testfiles[0]
        key.export(filepath, password)
        with open(filepath, "r") as file:
            self.assertTrue(file.read().strip() == private_pem)

        key.export(filepath)
        with open(filepath, "r") as file:
            self.assertTrue(file.read().strip() == public_pem)
    
    def test_public_key_import_export(self):
        ring: PublicKeyRing = PublicKeyRing.get_instance(username)
        key = ring.add_key(public_pem, "jane", "jane@gmail.com", 50, [])
        self.assertTrue(65537 == key.public.e)

        filepath = testfiles[0]
        key.export(filepath)
        with open(filepath, "r") as file:
            self.assertTrue(file.read().strip() == public_pem)


    def test_file_consistency(self):
        ring: PrivateKeyRing = PrivateKeyRing.get_instance(username)
        ring.generate_key(password, 2048)
        ring2: PrivateKeyRing = PrivateKeyRing(username)
        self.assertTrue(ring.get_all() == ring2.get_all())

        ring: PublicKeyRing = PublicKeyRing.get_instance(username)
        ring.add_key(public_pem, "Jane", "jean@gmail.com", 50, [])
        ring2: PublicKeyRing = PublicKeyRing(username)
        self.assertTrue(ring.get_all() == ring2.get_all())

    def test_public_key_trust(self):
        ring: PublicKeyRing = PublicKeyRing.get_instance(username)
        user1 = "jane@gmail.com"
        user2 = "tom@gmail.com"
        janeKey = ring.add_key(public_pem, "Jane", user1, 50, [])
        tomKey = ring.add_key(public_pem2, "Tom", user2, 40, [])

        janeKeys = ring.get_keys(user1)
        tomKeys = ring.get_keys(user2)
        self.assertTrue(len(janeKeys) == 1)
        self.assertTrue(len(tomKeys) == 1)

        self.assertTrue(janeKey.owner_trust == 50)
        self.assertTrue(janeKey.legitimacy == False)

        janeKey.add_signature("tom@gmail.com")
        self.assertTrue(janeKey.trust_score == 40)
        janeKey.add_signature(username)
        self.assertTrue(janeKey.trust_score == 140)
        self.assertTrue(janeKey.legitimacy == True)

        ring.set_owner_trust(user2, 90)
        self.assertTrue(janeKey.trust_score == 190)
        



if __name__ == "__main__":
    unittest.main()