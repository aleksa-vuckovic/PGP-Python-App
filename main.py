import tkinter
from tkinter import ttk
from pgp_send_message import send_pgp_message_module_init
from pgp_receive_message import receive_message_frame_module_init
from ui import PrivateKeysScreen

window = tkinter.Tk()
window.title("PGP simulation project")
window.geometry("800x600")

notebook = ttk.Notebook(window)
sending_message_frame=send_pgp_message_module_init()
receiving_message_frame=receive_message_frame_module_init()
private_keys_frame=PrivateKeysScreen(None)


notebook.add(sending_message_frame,text="Send Message")
notebook.add(receiving_message_frame,text="Receive Message")
notebook.add(private_keys_frame, text="Private Keys")
notebook.pack(fill="both",expand=True)

window.mainloop()
