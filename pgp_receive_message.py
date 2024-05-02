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

text_area=None



def receive_message_frame_module_init():

    def decrypt_message(message,algo,params):
        if algo=="AES":
            aes_handle=AES.new(params[0],AES.MODE_CFB,params[1])
            return unpad(aes_handle.decrypt(message),AES.block_size)
        else: #TripleDES
            triple_des_handle=DES3.new(params[0],DES3.MODE_CFB,params[1])
            return unpad(triple_des_handle.decrypt(message),DES3.block_size)
    def receive_message():
        choosen_filename = askopenfile()

        if not choosen_filename:
            messagebox.showinfo("Info", "Choose correct directory!")
            return


        ciphertext = dict()
        print(choosen_filename.name)
        with open(choosen_filename.name, "r") as file:
            ciphertext=file.read()
            ciphertext=ast.literal_eval(ciphertext)


            #ciphertext=eval(ciphertext)

        if "radix" in ciphertext:
            ciphertext=eval(base64.b64decode(ciphertext["radix"].encode("ascii")).decode("ascii"))

            radix_label.config(text="Radix64 ✓")
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
                print("----a---")

                PRb=private_data.decode(passphrase)

            except Exception:
                messagebox.showinfo("Error","Wrong password!")
                return


            rsa_encr = PKCS1_OAEP.new(PRb)
            Ks=rsa_encr.decrypt(Ks)

            ciphertext=decrypt_message(msg,algoritham,(Ks,params[1]))
            ciphertext=eval(ciphertext)
            print(ciphertext)
            encryption_label.config(text="Encryption ✓")

            #pass

        if "zip" in ciphertext:
            ciphertext=eval(zlib.decompress(ciphertext["zip"]).decode("utf-8"))
            zip_label.config(text="Zip ✓")

            print("zip")
            print(ciphertext)

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

            print(pkcs.verify(hash,signature))

            print(ciphertext)
            authentication_label.config(text="Authentication ✓")
            ciphertext=msg

        # Insert the ciphertext into the text area
        text_area.config(state="normal")  # Enable the text area for editing
        text_area.delete(1.0, END)  # Clear previous content if any
        text_area.insert(END, ciphertext)  # Insert the ciphertext
        text_area.config(state="disabled")  # Disable the text area again

        pass


    receiving_message_frame=tkinter.Frame()

    authentication_label = tkinter.Label(receiving_message_frame, text="Authentication", font=("Arial", 16))
    authentication_label.place(x=60, y=50)

    zip_label = tkinter.Label(receiving_message_frame, text="Zip", font=("Arial", 16))
    zip_label.place(x=250, y=50)

    encryption_label = tkinter.Label(receiving_message_frame, text="Encryption", font=("Arial", 16))
    encryption_label.place(x=350, y=50)

    radix_label = tkinter.Label(receiving_message_frame, text="Radix-64", font=("Arial", 16))
    radix_label.place(x=550, y=50)

    text_label = tkinter.Label(receiving_message_frame, text="Text", font=("Arial", 16))
    text_label.place(x=10, y=300)

    text_area = tkinter.Text(receiving_message_frame, height=5, width=100,state="disabled")
    text_area.place(x=200, y=300)

    B = Button(receiving_message_frame, text="Receive message", command=receive_message)
    B.place(x=400, y=400)

    return receiving_message_frame