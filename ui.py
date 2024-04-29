import tkinter as tk
from keys import PublicKeyRing, PrivateKeyRing, PublicKeyData, PrivateKeyData
import datetime

def clear(frame: tk.Frame | tk.Tk):
    for child in frame.winfo_children():
        child.destroy()


class HomeScreen(tk.Frame):

    def __init__(
            self,
            master: tk.Misc,
            on_private_ring,
            on_public_ring,
            on_send,
            on_receive
    ):
        super().__init__(master)

        private = tk.Button(self, text = "Private keys", command=on_private_ring)
        private.grid(row = 0, column = 0, padx = 10, pady = 10)

        public = tk.Button(self, text = "Public keys", command=on_public_ring)
        public.grid(row = 0, column = 1, padx = 10, pady = 10)

        send = tk.Button(self, text = "Send message", command=on_send)
        send.grid(row = 1, column = 0, padx = 10, pady = 10)

        receive = tk.Button(self, text = "Receive message", command=on_receive)
        receive.grid(row = 1, column = 1, padx = 10, pady = 10)

class ScrollBar(tk.Frame):
    def __init__(self, master, on_up, on_down, **kwds):
        """
        Args:
            on_up: Callback method for up scroll.
            on_down: Call back method for down scroll.
        """
        super().__init__(master, **kwds)
        self.up_button = tk.Button(self, text="⌃", command=on_up)
        self.down_button = tk.Button(self, text="⌄", command=on_down)
        self.up_button.grid(row = 0, column=0,ipadx=5,ipady=5,sticky="N")
        self.down_button.grid(row = 1, column=0, ipadx=5,ipady=5,sticky="S")
        self.segments = []

    def set_range(self, total):
        """The total number of rows covered by this scrollbar."""
        for elem in self.segments: elem.destroy()
        self.segments = []
        for i in range(total):
            seg = tk.Frame(self, bg="")
            seg.grid(row = i+1, column = 0, sticky="NSEW")
            self.segments.append(seg)
            self.grid_rowconfigure(i+1, weight=1)
        self.down_button.grid(row = total+1, column = 0, ipadx=5,ipady=5,sticky="S")
    
    def set_current(self, a, b):
        for i, elem in enumerate(self.segments):
            if i in range(a, b): elem.config(bg="black")
            else: elem.config(bg="lightgrey")
        if 0 in range(a,b): self.up_button.config(state="disabled")
        else: self.up_button.config(state="normal")
        if len(self.segments)-1 in range(a,b): self.down_button.config(state="disabled")
        else: self.down_button.config(state="normal")

class ScrollTable(tk.Frame):
    """
    A scrollable table with arrow buttons.
    """
    def __init__(self,
                 master: tk.Misc,
                 visible_rows: int,
                 headers,
                 **kwds):
        """
        Args:
            visible_rows (int): The maximum number of rows visible simultaneously.
            headers: List of strings, headers for each column.
        """
        super().__init__(master, **kwds)
        self.visible_rows = visible_rows
        self.headers = headers
        self.content = []

        self.table_frame = tk.Frame(self)
        self.table_frame.grid(row = 0, column = 0, sticky="N")
        self.scrollbar = ScrollBar(self, self.scroll_up, self.scroll_down)
        self.scrollbar.grid(row = 0, column=1, sticky="NSEW")
        
        self.a = 0 #currently displayed first row
        self.set_content(None, 0)

    def set_content(self, get_elem, row_count):
        """
        Args:
            get_elem: A callback method which takes a Frame as the first
                and row and column index as the second and third argument,
                and returns a widget to be be displayed at the specified position, or None if row is out of range.
            row_count: Total number of rows.
        """
        i = 0

        clear(self.table_frame)
        self.content = []
        for j, text in enumerate(self.headers):
            tk.Label(self.table_frame, text=text).grid(row = 0, column=j)
        for i in range(row_count):
            elems = []
            for j in range(len(self.headers)):
                frame = tk.Frame(self.table_frame, relief="solid", borderwidth=1)
                elem = get_elem(frame, i, j)
                elem.grid(row = 0, column = 0)
                frame.grid_rowconfigure(0, weight=1)
                frame.grid_columnconfigure(0, weight=1)
                elems.append(frame)
            self.content.append(elems)
        self.scrollbar.set_range(len(self.content))
        self.a = 0
        self.update()

    def update(self):
        """Scroll update"""
        total = len(self.content)
        mina = 0
        maxa = total-self.visible_rows if total-self.visible_rows > 0 else 0
        if self.a <= mina: self.a = mina
        if self.a >= maxa: self.a = maxa

        b = self.a + self.visible_rows
        if b > total: b = total

        for i in range(len(self.content)):
            for j in range(len(self.headers)):
                if i < self.a or i >= b: self.content[i][j].grid_forget()
                else: self.content[i][j].grid(row = i-self.a+1, column=j, sticky="NSEW", ipadx = 10, ipady = 10)
                j += 1
        
        self.scrollbar.set_current(self.a, b)



    def scroll_up(self):
        self.a -= 1
        self.update()

    def scroll_down(self):
        self.a += 1
        self.update()

"""
1. Table
2. Import, Generate
3. Details
    -Public: n, e, export
    -Private: p, q, d, export
"""
class PrivateKeyScreen(tk.Frame):

    def __init__(self, master: tk.Misc, ring: PrivateKeyRing, on_details, on_import, on_generate):
        """
        Args:
            on_details: A callback which takes the PrivateKeyData object as argument.
            on_import, on_generate: Callbacks with no arguments.
        """
        super().__init__(master)
        self.ring = ring
        self.on_details = on_details
        self.on_import = on_import
        self.on_generate = on_generate

        """
        Public key ring
        x   table   x
        Import Generate
        """

        title = tk.Label(self, text = "Private key ring", justify="center", anchor="w", font=("Helvetica", 14, "bold"))
        title.grid(row = 0, column = 0, sticky = "NSEW", padx=20, pady=10)

        self.table = ScrollTable(self, visible_rows=5, headers=["Timestamp", "Key ID", "Public exp", "Name", "Email", ""])
        self.table.grid(row = 1, column = 0, padx=10, pady=10)

        commands = tk.Frame(self)
        commands.grid(row = 2, column = 0, ipadx=20, ipady=10, sticky="NSEW")
        commands.grid_columnconfigure(0, weight=1)
        commands.grid_columnconfigure(1, weight=1)
        impor = tk.Button(commands, text = "Import", command=self.on_import)
        impor.grid(row = 0, column = 0)
        generate = tk.Button(commands, text = "Generate", command = self.on_generate)
        generate.grid(row = 0, column = 1)
        
        self.refresh()
        
    
    def refresh(self):
        self.table.set_content(self.get_elem, len(self.ring.get_all()))
    
    def get_elem(self, master, i, j):
        if i >= len(self.ring.get_all()): return None
        key = list(self.ring.get_all().values())[i]
        if j == 0:
            text = datetime.datetime.fromtimestamp(key.timestamp).strftime("%Y-%m-%d %H:%M")
            return tk.Label(master, text = text)
        if j == 1:
            return tk.Label(master, text = key.key_id, width=18)
        if j == 2:
            return tk.Label(master, text = str(key.public.e), width=6, wraplength=30)
        if j == 3:
            return tk.Label(master, text = key.name, width=12, wraplength=60)
        if j == 4:
            return tk.Label(master, text = key.email, width=25, wraplength=125)
        if j == 5:
            return tk.Button(master, text="Details", command=lambda: self.on_details(key))
        raise Exception("Unexpected j value.")
        

