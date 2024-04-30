import tkinter
from tkinter import ttk
from pgp_send_message import send_pgp_message_module_init
from pgp_receive_message import receive_message_frame_module_init


print("Hello".encode())



window = tkinter.Tk()
window.title("PGP simulation project")
window.geometry("800x600")

notebook = ttk.Notebook(window)



sending_message_frame=send_pgp_message_module_init()
receiving_message_frame=receive_message_frame_module_init()


notebook.add(sending_message_frame,text="Sending Messages")
notebook.add(receiving_message_frame,text="Receive Message")

notebook.pack(fill="both",expand=True)

window.mainloop()

