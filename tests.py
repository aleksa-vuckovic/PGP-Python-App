import unittest
import shutil
from keys import PrivateKeyRing, PublicKeyRing
import rsa
import os
from exceptions import *


private_pem = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwuzm0MXHd3GBlbywDY9SJYqcu6a5GbhHzXtuWoilwXUwQehP
HbGyMbm/X2bFZuet/uaEDIWNoz8cYz2G089ahy/qXNujlTMomccFWEGLh+Tt8e2E
o3VFcXOLcwT0/olYmoP1CtEGKTuUz1LEWQe5GGU9lRZyaEhoHqnRZv7Q7rPgqFFW
Gb/lNkaBJOWBFwY9QsCMk10a4n4z3lGakpsUygnDBL4i7SQJo32xFljJpAw1JKob
8YFgp3n2QgugJHNjQ+TFTJSCWCYSBNml1EuQPg0yyRM0OiaAoBove4YqdDahJqt1
3tumKUBJ1LGzyzGKBy+/9E5xEvhBW1UrXHDWcQIDAQABAoIBABS9Wg2qjX+S7yO8
cMrwjd/6sJRyt80Zw2IEmQg+88vyqRDKI+jX6ErMJaWD7Mr3KZcudaxTZW+SHnYc
rMTKkipCGeCJag1M5Sv/df0e9DagUATmra8qohnhHlw9kcenW2sNUTw2Yz5t3XZ1
qviCDtqeov/C5Kdd1N42WVZpFFfhUfU22zGpqzLmNu8kI8pGmR/qBnwa01EOhb1I
z6FcF68F6GbTqQFDLMZrbKdazNobp60Vpfrr5qSKndR7JCv+aqvI6CEpO9eIN+4Y
wX7v7IaSr+9He2sKeo3elOGXgB6R/2ALMHxPUpQ7psw3kABn3FHqHC8LE+qMCv+x
ij/mdLECgYEA88jzuyX56cavsK/PZZrPezCfDE1o25YYgbuhCvsp+E38QfRl5DOS
8W1eYEwlmFjEA6eola5LHNv8ueSc5A2A9c12oHO1CcyM4w4sszTFiuKgxL4bD+jT
YDGRisb7FOsXXwbdD/Grng4/7WBEsLKbSK3AxNB/mooGKl3yiDD50m0CgYEAzLE5
ZChHLjBtcd8cY0fYy3NXavmUX8HPuwbzfe0j5vPmKz0PFQWOYF4PDIxlMCjKM7zD
u+qEhCxdie+f+spg8jWlsaOgLXBkTLntUhaa7ixGtPlCITbujD7D3uOYa+s3DOOK
F6w2bH7HawjhT5tv79rLYlWnl+ErKJXC5qs8sZUCgYB3ABXxugT3V9R1RCzSJTK4
qLBKuhLAddE6qtNe3+HJ4o+LxnhiX8aP8VpLWYBUkKgGPLYvcqgZy0zflTf8npbf
5c7NXg32XZI8V7P8OntfY2clAsOFDZr47tljy+POfz+mVFxepxKmEcCk6AQ/2L+y
R5a8vCY90rhVwAxe7MFWNQKBgQCL0wRBRsJY6vvYLXBW4V1WnRO6H4MbZmlgeP8b
pkJAIZu5LZx/36vCaH4fNEhq/XIipW+PjkO3hhbfgrDlwBk5Wyw0jHF+mKfrQZa7
3HU4/UXPmfVyevO5GabzOsWD8slIJKbQRPNoabIPi6Fdn/B3CB6mrZwuQ8IXlzXs
HEz5gQKBgQDcRMbKZuZvJVKtfesX9fNJymawr5ZvGtN5KRBnW7qPnwm1mqcO6lVF
YlLDE3GSuqq/YQwHYwWiaVOTZu09fT64oM8vA9tegUVbDNAF8Zg5KwHfFYSP5pIg
9Yl89kh2cbsrEWsRtS783gRHh2Hf8cowStNBp/GGxwzPpCCw3yWAvw==
-----END RSA PRIVATE KEY-----"""
public_pem = """-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAwuzm0MXHd3GBlbywDY9SJYqcu6a5GbhHzXtuWoilwXUwQehPHbGy
Mbm/X2bFZuet/uaEDIWNoz8cYz2G089ahy/qXNujlTMomccFWEGLh+Tt8e2Eo3VF
cXOLcwT0/olYmoP1CtEGKTuUz1LEWQe5GGU9lRZyaEhoHqnRZv7Q7rPgqFFWGb/l
NkaBJOWBFwY9QsCMk10a4n4z3lGakpsUygnDBL4i7SQJo32xFljJpAw1JKob8YFg
p3n2QgugJHNjQ+TFTJSCWCYSBNml1EuQPg0yyRM0OiaAoBove4YqdDahJqt13tum
KUBJ1LGzyzGKBy+/9E5xEvhBW1UrXHDWcQIDAQAB
-----END RSA PUBLIC KEY-----"""
public_pem2 = """-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAytdMINlJduGQG2CZAx27v2ert18iJINoAOcVw1moHNJm96+70YK3
okSBZJ3YEbsQk4spBh7MjN1AFS6W9yTmPhUwHmjEKeHSseVMdJTq2SaX3LrRiFkE
Ke2eC9y9nyfLD7hveKR329RRnzY0s4Zhy2tN2GDrRa5VRBvY+mKaeDlWSR0qvhCO
tok4HrB8jsYiD2a75bghKHg0UlLk/OhusK6YktvDH5U9NVXFoMSytSA8rJCnTK+r
UjrxWLDs5w4S14ppeb15JdFuhylAA7LzcMHgw6zZs8yd2e4DodCSBqD9w5RS47X4
fYDP7px8Hqltowu3DYryBqpU3uIHcESoXwIDAQAB
-----END RSA PUBLIC KEY-----"""


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
        enc = rsa.encrypt(msg, public)
        dec = rsa.decrypt(enc, private)
        self.assertTrue(msg == dec)

        with self.assertRaises(DisplayableException):
            key.decode("badpass")
    
    def test_private_key_import_export(self):
        ring: PrivateKeyRing = PrivateKeyRing.get_instance(username)
        key = ring.import_key(private_pem, password)
        private = key.decode(password)
        public = key.public
        msg = b"Hello"
        enc = rsa.encrypt(msg, public)
        dec = rsa.decrypt(enc, private)
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