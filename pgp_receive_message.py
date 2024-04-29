import tkinter
from tkinter import *

text_area=None

def receive_message():
    pass

def receive_message_frame():
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

    text_area = tkinter.Text(receiving_message_frame, height=5, width=100)
    text_area.place(x=200, y=300)

    B = Button(receiving_message_frame, text="Receive message", command=receive_message)
    B.place(x=400, y=400)

    return receiving_message_frame