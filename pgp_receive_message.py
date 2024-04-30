import ast
import base64
import tkinter
import zlib
from tkinter import *
from tkinter import messagebox
from tkinter.filedialog import askopenfile
from tkinter.simpledialog import askstring

from keys import PrivateKeyRing, PrivateKeyData, PublicKeyRing, PublicKeyData

from Cryptodome.Hash import SHA1
from Cryptodome.Signature import pkcs1_15

import json

text_area=None



def receive_message_frame_module_init():
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

        if "Ks" in ciphertext:
            pass

        if "zip" in ciphertext:
            ciphertext=eval(zlib.decompress(ciphertext["zip"]).decode("utf-8"))


        if "signature" in ciphertext:
            signature=ciphertext["signature"]
            PUa_mod=ciphertext["pua_mod"]
            msg=ciphertext["msg"]

            passphrase=askstring("Input", "Input an passphrase:")

            publicRing: PublicKeyRing = PublicKeyRing.get_instance()
            print(PUa_mod)
            try:
                publicData: PublicKeyData = publicRing.get_key(int(PUa_mod,16))  # id is PUa%2^64
            except Exception:
                messagebox.showinfo("Warning","This key does not exists in public ring!")
                return
            rsa = None

            try:
                rsa = publicData.decode(passphrase)
            except Exception:
                messagebox.showinfo("Info", "Error wrong password!")
                return

            hash = SHA1.new(str(msg).encode('utf-8'))

            try:
                pkcs1_15.new(rsa).verify(hash, signature)
            except (ValueError, TypeError):
                messagebox.showinfo("Error","Wrong message!")




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