
from abc import ABC, abstractmethod

import base64
import datetime
import tkinter
import zlib
from tkinter import ttk, messagebox
from tkinter.simpledialog import askinteger, askstring
from tkinter import *
from tkinter.filedialog import askopenfile

from Cryptodome.Cipher import AES, DES3, PKCS1_OAEP
from Cryptodome.Hash import SHA1
from tkinter.filedialog import asksaveasfilename

from Cryptodome.Random import get_random_bytes
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Util.Padding import pad

from keys import PrivateKeyRing, PrivateKeyData, PublicKeyRing

from pprint import pprint

#interface
class Handler(ABC):
    """
        The Handler interface declares a method for building the chain of handlers.
        It also declares a method for executing a request.
    """

    @abstractmethod
    def set_next(self,handler):
        pass

    @abstractmethod
    def handle(self,request,params):
        pass

class AbstractHandler(Handler):

    _next_handler:Handler=None

    def set_next(self,handler:Handler)->Handler:
        self._next_handler=handler

        return handler

    def handle(self,request,params):
        print(self._next_handler)
        if self._next_handler:
            return self._next_handler.handle(request,params)
        return request


'''
    Concrete handlers.
'''

class AuthenticationSender(AbstractHandler):

    def handle(self,request,params):

        if params["authentication_flag"].get()==1:
            auth = {}
            hash = SHA1.new(str(request).encode('utf-8'))

            privateRing: PrivateKeyRing = PrivateKeyRing.get_instance()
            try:
                privateData: PrivateKeyData = privateRing.get_key(params["PUa_mod"])  # id is PUa%2^64
            except Exception:
                messagebox.showinfo("Error", "You have to choose correct algorithm and key. Try again!")
                return

            PRa = None
            try:
                passphrase = askstring("Input", "Input an passphrase:")
                PRa = privateData.decode(passphrase)
            except Exception:
                messagebox.showinfo("Info", "Error wrong password!")
                return

            auth_signature = pkcs1_15.new(PRa).sign(hash)  # Create the PKCS1 v1.5 signature of a message.

            auth["msg"] = request
            auth["signature"] = auth_signature
            auth["pua_mod"] = params["PUa_mod"]
            request = auth

            return super().handle(request,params)
        else:
            return super().handle(request, params)
class ZipSender(AbstractHandler):

    def handle(self,request,params):
        if params["zip_f"]:
            zip = {}
            zip["zip"] = zlib.compress(str(request).encode('utf-8'))
            request = zip

            return super().handle(request,params)
        else:
            return super().handle(request,params)

class EncryptionSender(AbstractHandler):


    def encrtyption_of_message(self,message,algoritham):

        if algoritham=="AES": #AES
            Ks = get_random_bytes(16)#size=16
            c=AES.new(Ks,AES.MODE_CFB)
            enc=c.encrypt(
                pad(bytearray(str(message).encode('utf-8')),AES.block_size)
            )
            return enc,(Ks,c.iv)
        else:#TripleDES
            Ks=get_random_bytes(24) #size=24
            c=DES3.new(Ks,DES3.MODE_CFB)
            enc=c.encrypt(
                pad(bytearray(str(message).encode('utf-8')),DES3.block_size)
            )
            return enc,(Ks,c.iv)

    def encryption_of_Ks(self,PUb):
        rsa_encr=PKCS1_OAEP.new(PUb)
        return rsa_encr
    def handle(self,request,params):

        if params["encryption_flag"].get()==1:

            encr = {}
            try:
                encrypted_message, params_b = self.encrtyption_of_message(request, params["enc_algo"])  # cipher,(Ks,IV)
            except Exception:
                messagebox.showinfo("Error", "You have to choose correct algorithm and key. Try again!")
                return

            encr["message"] = encrypted_message
            encr["pub_mod"] = params["PUb"] % pow(2, 64)

            public_ring = PublicKeyRing.get_instance()
            rsa_key = None
            try:
                rsa_key = public_ring.get_key(hex(params["PUb"])).public
            except Exception:
                pass

            tmp_pub = self.encryption_of_Ks(rsa_key)

            encr["Ks"] = tmp_pub.encrypt(params_b[0])  # encrypted Ks
            encr["algoritham"] = params["enc_algo"]
            encr["iv"] = params_b[1]

            request = encr

            return super().handle(request, params)
        else:
            return super().handle(request, params)

class RadixSender(AbstractHandler):

    def radix64_encription(self,message):
        return base64.b64encode(str(message).encode('ascii')).decode('ascii')
    def handle(self,request,params):

        if params["radix64_f"]:
            radix = {}
            radix["radix"] = self.radix64_encription(request)
            request = radix

            return super().handle(request, params)
        else:
            return super().handle(request, params)
