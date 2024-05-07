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

from MessageHandling.MessageSending import *




def authentication_list_refresh():
    private_ring_ids=[key for key in PrivateKeyRing.get_instance().get_all().keys()]
    authentication_private_key_id_list.config(values=private_ring_ids)
def encryption_list_refresh():
    public_ring_ids=[key for key in PublicKeyRing.get_instance().get_all().keys()]
    encryption_public_key_id_list.config(values=public_ring_ids)


def send_pgp_message_module_init():
    # pgp_sending_message_init (must be after createing window)

    authentication_flag = tkinter.IntVar()
    authentication_private_key_id = tkinter.StringVar()

    encryption_flag = tkinter.IntVar()
    encryption_public_key_id = tkinter.StringVar()
    encryption_alorithm_var = tkinter.StringVar(value="AES")

    zip_flag = tkinter.IntVar()

    radix_flag = tkinter.IntVar()

    passphrase_password = None

    #listeners
    def on_state_change_authentication_checkbox():
        if authentication_flag.get()!=1:
            authentication_label_private_key.config(state="disabled")
            authentication_private_key_id_list.config(state="disabled")
        else:
            authentication_label_private_key.config(state="normal")
            authentication_private_key_id_list.config(state="readonly")
    def on_state_change_encryption_checkbox():
        if encryption_flag.get()==1:
            encryption_label_users.config(state="normal")
            encryption_public_key_id_list.config(state="readonly")
            encryption_algorithm.config(state="readonly")
        else:
            encryption_label_users.config(state="disabled")
            encryption_public_key_id_list.config(state="disabled")
            encryption_algorithm.config(state="disabled")


    #encription
    def sha1_hash_for_password(passphrase):
        passphrase_password=passphrase
        passphrase_bytearay=bytearray(passphrase.encode('utf-8')) #Creaton of bytearray from string

        sha1_factory=SHA1.new() #Create a new hash object
        sha1_factory.update(passphrase_bytearay) #Continue hashing of a message by consuming the next chunk of data.

        passphrase_hash=sha1_factory.hexdigest()

        return passphrase_hash #Return the printable digest of the message that has been hashed so far.

    def authentication_passphrase_dialog(MouseClicked):
        global passphrase
        '''
        passphrase = askstring("Input", "Input an passphrase:")
        passphrase_hash = sha1_hash_for_password(passphrase)

        if passphrase_hash != "40bd001563085fc35165329ea1ff5c5ecbdbbeef":  # hire you should switch with real hash
            messagebox.showinfo("Info:", "Wrong password!")
            return None
        else:
            messagebox.showinfo("Info:", "Password is valid!")
            return passphrase
        '''


    def send_message():
        #ask for directory->returns name of directory
        choosen_directory=asksaveasfilename(defaultextension=".txt")
        if not choosen_directory:
            messagebox.showinfo("Info","Choose correct directory!")
            return
        #extracting neccesary atriutes from gui comp.
        PUa_mod,PUb,enc_algo,zip_f,radix64_f,text=None,None,None,False,False,None

        if authentication_flag.get()==1:
            PUa_mod=authentication_private_key_id.get()
        if zip_flag.get()==1:
            zip_f=True
        if encryption_flag.get()==1:
            PUb=int(encryption_public_key_id_list.get(),16)
            enc_algo=encryption_alorithm_var.get()
        if radix_flag.get()==1:
            radix64_f=True
        text=text_area.get("1.0","end-1c")

        print(PUa_mod,PUb,enc_algo,zip_f,radix64_f)
        print(text)
        print(choosen_directory)
        #wrapping message

        message={
            "msg":text,
            "timestamp":str(datetime.datetime.now()),
            "file":choosen_directory
        }

        print(message)

        sending_frame={
            "authentication_flag":authentication_flag,
            "PUa_mod":PUa_mod,
            "zip_f":zip_f,
            "encryption_flag":encryption_flag,
            "enc_algo":enc_algo,
            "PUb":PUb,
            "radix64_f":radix64_f
        }

        auth_sender=AuthenticationSender()
        zip_sender=ZipSender()
        encrypt_sender=EncryptionSender()
        radix_sender=RadixSender()

        auth_sender.set_next(zip_sender).set_next(encrypt_sender).set_next(radix_sender)

        message=auth_sender.handle(message,params=sending_frame)

        with open(choosen_directory,"w") as file:
            print(str(message))
            file.write(str(message))

        return

    def creation_of_sending_message_frame():

        sending_message_frame = tkinter.Frame()

        return sending_message_frame



    #sending message frame
    sending_message_frame=creation_of_sending_message_frame()

    #Title label
    sending_essage_label=tkinter.Label(sending_message_frame,text="Send Message",font=("Arial",16))
    sending_essage_label.pack(padx=100,pady=0)


    #authentication
    authentication_label=tkinter.Label(sending_message_frame,text="Authentication:",font=("Arial",16))
    authentication_label.place(x=10,y=50)

    authentication_checkbox=tkinter.Checkbutton(sending_message_frame,text="Choose",command=on_state_change_authentication_checkbox,variable=authentication_flag)
    authentication_checkbox.place(x=200,y=50) #after selecting this, authentication_label_private_key shouldnt be disabled

    authentication_label_private_key=tkinter.Label(sending_message_frame,text="Private key:",state="disabled",font=("Arial",16))
    authentication_label_private_key.place(x=300,y=50)


    global private_ring_ids
    private_ring_ids=[key for key in PrivateKeyRing.get_instance().get_all().keys()]

    global authentication_private_key_id_list
    authentication_private_key_id_list=ttk.Combobox(sending_message_frame,textvariable=authentication_private_key_id,values=private_ring_ids,state="disabled")
    authentication_private_key_id_list.place(x=550,y=50)
    authentication_private_key_id_list.bind("<<ComboboxSelected>>", authentication_passphrase_dialog)


    #encryption
    encryption_label=tkinter.Label(sending_message_frame,text="Encryption:",font=("Arial",16))
    encryption_label.place(x=10,y=100)

    enctyption_checkbox=tkinter.Checkbutton(sending_message_frame,text="Choose",command=on_state_change_encryption_checkbox,variable=encryption_flag)
    enctyption_checkbox.place(x=200,y=100)

    encryption_label_users=tkinter.Label(sending_message_frame,text="Public key:",font=("Arial",16),state="disabled")
    encryption_label_users.place(x=300,y=100)

    global public_ring_ids
    public_ring_ids=[key for key in PublicKeyRing.get_instance().get_all().keys()] #- this will be added later

    global encryption_public_key_id_list
    encryption_public_key_id_list=ttk.Combobox(sending_message_frame,textvariable=encryption_public_key_id,values=public_ring_ids,state="disabled")
    encryption_public_key_id_list.place(x=550,y=100)

    encryption_algorithm=ttk.Combobox(sending_message_frame,text="Choose algorithm",textvariable=encryption_alorithm_var,values=["TripleDES","AES"],state="disable")
    encryption_algorithm.place(x=700,y=100)



    #zip
    zip_label=tkinter.Label(sending_message_frame,text="Zip:",font=("Arial",16))
    zip_label.place(x=10,y=150)
    zip_checkbox=tkinter.Checkbutton(sending_message_frame,text="Choose",variable=zip_flag)
    zip_checkbox.place(x=200,y=150)

    #radix-64
    radix_label=tkinter.Label(sending_message_frame,text="Radix-64:",font=("Arial",16))
    radix_label.place(x=10,y=200)
    radic_checkbox=tkinter.Checkbutton(sending_message_frame,text="Choose",variable=radix_flag)
    radic_checkbox.place(x=200,y=200)


    #text - that will be ciphered
    text_label=tkinter.Label(sending_message_frame,text="Text:",font=("Arial",16))
    text_label.place(x=10,y=300)

    text_area=tkinter.Text(sending_message_frame,height=5,width=100)
    text_area.place(x=200,y=300)

    B = Button(sending_message_frame, text ="Send message", command=send_message)
    B.place(x=400,y=400)

    return sending_message_frame
