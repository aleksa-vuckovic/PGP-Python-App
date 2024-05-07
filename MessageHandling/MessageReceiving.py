from abc import ABC, abstractmethod

import ast
import base64
import tkinter
import zlib
from tkinter import *
from tkinter import messagebox
from tkinter.filedialog import askopenfile
from tkinter.simpledialog import askstring

from Cryptodome.Cipher import AES, DES3, PKCS1_OAEP
from Cryptodome.Util.Padding import unpad

from keys import PrivateKeyRing, PrivateKeyData, PublicKeyRing, PublicKeyData

from Cryptodome.Hash import SHA1
from Cryptodome.Signature import pkcs1_15

import json


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

        if self._next_handler:
            return self._next_handler.handle(request,params)
        return request

'''
    Concrete handlers.
'''

class AuthenticationReceiver(AbstractHandler):

    def handle(self,ciphertext,params):

        if "pua_mod" in ciphertext:
            print("pua_mod")
            signature=ciphertext["signature"]
            PUa_mod=ciphertext["pua_mod"]
            msg=ciphertext["msg"]
            print("pua2)")

            #passphrase=askstring("Input", "Input an passphrase:")
            print("pua3")
            publicRing: PublicKeyRing = PublicKeyRing.get_instance()
            publicData=None

            print(PUa_mod)
            try:
                publicData: PublicKeyData = publicRing.get_key(PUa_mod)  # id is PUa%2^64
            except Exception:
                messagebox.showinfo("Warning","This key does not exists in public ring!")
                return


            hash = SHA1.new(str(msg).encode('utf-8'))

            pd=publicRing.get_key(PUa_mod)

            print(hash)
            pkcs=pkcs1_15.new(pd.public)

            try:
                pkcs.verify(hash,signature)
            except Exception:
                messagebox.showinfo("Warning","Signature is not correct, somebody changed the message!")
                return

            print(ciphertext)
            params["authentication_label"].config(text="Authentication ✓")
            ciphertext=msg

            return super().handle(ciphertext,params)
        else:
            return super().handle(ciphertext,params)

class ZipReciever(AbstractHandler):

    def handle(self,ciphertext,params):
        if "zip" in ciphertext:
            ciphertext=eval(zlib.decompress(ciphertext["zip"]).decode("utf-8"))
            params["zip_label"].config(text="Zip ✓")

            return super().handle(ciphertext,params)
        else:
            return super().handle(ciphertext,params)


class EncryptionReciever(AbstractHandler):

    def decrypt_message(self,message,algo,params):
        if algo=="AES":
            aes_handle=AES.new(params[0],AES.MODE_CFB,params[1])
            return unpad(aes_handle.decrypt(message),AES.block_size)
        else: #TripleDES
            triple_des_handle=DES3.new(params[0],DES3.MODE_CFB,params[1])
            return unpad(triple_des_handle.decrypt(message),DES3.block_size)
    def handle(self,ciphertext,params_l):

        if "Ks" in ciphertext:
            Ks=ciphertext["Ks"]
            PUb_mod=ciphertext["pub_mod"]
            algoritham=ciphertext["algoritham"]
            params=ciphertext["params"]
            msg=ciphertext["message"]

            #decription of Ks

            PRb=None
            try:
                passphrase=askstring("Input", "Input an passphrase:")
                private_ring=PrivateKeyRing.get_instance()
                print(hex(PUb_mod))
                private_data=private_ring.get_key(hex(PUb_mod))


                PRb=private_data.decode(passphrase)

            except Exception:
                messagebox.showinfo("Error","Wrong password!")
                return


            rsa_encr = PKCS1_OAEP.new(PRb)
            Ks=rsa_encr.decrypt(Ks)

            ciphertext=self.decrypt_message(msg,algoritham,(Ks,params[1]))
            ciphertext=eval(ciphertext)
            print(ciphertext)
            params_l["encryption_label"].config(text="Encryption ✓")

            return super().handle(ciphertext,params_l)
        else:
            return super().handle(ciphertext,params_l)


class RadixReceiver(AbstractHandler):
    def handle(self,ciphertext,params):
        if "radix" in ciphertext:
            ciphertext = eval(base64.b64decode(ciphertext["radix"].encode("ascii")).decode("ascii"))

            params["radix_label"].config(text="Radix64 ✓")

            return super().handle(ciphertext,params)
        else:
            return super().handle(ciphertext,params)


