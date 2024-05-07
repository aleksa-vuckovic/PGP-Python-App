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

from MessageHandling.MessageReceiving import *

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

        radix_label.config(text="Radix64")
        encryption_label.config(text="Encryption")
        zip_label.config(text="Zip")
        authentication_label.config(text="Authentication")


        params={
            "authentication_label":authentication_label,
            "zip_label":zip_label,
            "encryption_label":encryption_label,
            "radix_label":radix_label
        }

        radix_receiver=RadixReceiver()
        encryption_receiver=EncryptionReciever()
        zip_receiver=ZipReciever()
        auth_receiver=AuthenticationReceiver()

        radix_receiver.set_next(encryption_receiver).set_next(zip_receiver).set_next(auth_receiver)

        ciphertext=radix_receiver.handle(ciphertext,params)

        # Insert the ciphertext into the text area
        text_area.config(state="normal")  # Enable the text area for editing
        text_area.delete(1.0, END)  # Clear previous content if any
        text_area.insert(END, ciphertext)  # Insert the ciphertext
        text_area.config(state="disabled")  # Disable the text area again




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