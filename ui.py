import tkinter as tk
from keys import PublicKeyRing, PrivateKeyRing, PublicKeyData, PrivateKeyData
import datetime
from tkinter import filedialog, messagebox, simpledialog
from Cryptodome.PublicKey import RSA
from exceptions import DisplayableException
def clear(frame: tk.Frame | tk.Tk):
    for child in frame.winfo_children():
        child.destroy()

class ScrollableFrame(tk.Frame):
    def __init__(self, container):
        super().__init__(container)
        self._canvas = tk.Canvas(self, highlightthickness=0)
        self._scrollbar = tk.Scrollbar(self, orient="vertical", command=self._canvas.yview)
        self.scrollable_frame = tk.Frame(self._canvas)
        self.scrollable_frame.bind("<Configure>", self.on_frame_configure)
        self._canvas.bind("<Configure>", self.on_canvas_configure)

        self._canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw", tags="tag")
        self._canvas.configure(yscrollcommand=self._scrollbar.set)
        self._scrollbar.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)
    def get_frame(self) -> tk.Frame:
        return self.scrollable_frame
    def on_frame_configure(self, event):
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))
        self._canvas.itemconfig("tag", width=event.width)
    def on_canvas_configure(self, event):
        self._canvas.itemconfig("tag", width=event.width)

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

class Title(tk.Label):
    def __init__(self, master, text):
        super().__init__(master, text = text, justify="center", anchor="w", font=("Helvetica", 14, "bold"))
        self.grid(row = 0, column = 0, sticky = "NSEW", padx=20, pady=10)

"""
1. Table
2. Import, Generate
3. Details
    -Public: n, e, export
    -Private: p, q, d, export
"""
class PrivateRingScreen(tk.Frame):

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

        title = Title(self, "Private Key Ring")
        
        self.table = ScrollTable(self, visible_rows=8, headers=["Timestamp", "Key ID", "Public exp", "Name", "Email", ""])
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
            return tk.Label(master, text = str(key.public.e), width=6, wraplength=36)
        if j == 3:
            return tk.Label(master, text = key.name, width=12, wraplength=72)
        if j == 4:
            return tk.Label(master, text = key.email, width=25, wraplength=150)
        if j == 5:
            return tk.Button(master, text="Details", command=lambda: self.on_details(key))
        raise Exception("Unexpected j value.")
        

"""
1. File or string
2. Name
3. Email
4. Import password?
5. Save password
"""
class ImportPrivateScreen(tk.Frame):
    def __init__(self, master: tk.Misc, on_import):
        """
        Args:
            on_import: A callback method which takes the pem text, name,
                email, import password and save password as arguments.
        """
        super().__init__(master)
        self.on_import = on_import
        Title(self, "Import Private Key")

        self.file = tk.BooleanVar(value = True)
        selection = tk.Frame(self)
        file = tk.Radiobutton(selection, text = "Import from PEM file", variable=self.file, value=True, command=self._refresh)
        textbox = tk.Radiobutton(selection, text = "Enter the text in PEM format", variable=self.file, value=False, command=self._refresh)
        file.grid(row=0, column=0, padx=20, pady=10)
        textbox.grid(row=0, column=1, padx=20, pady=10)
        selection.grid(row = 1, column = 0)
        self.file.set(True)
        
        input = tk.Frame(self)
        self.selected_file = tk.Entry(input)
        self.select_file_button = tk.Button(input, text = "Select File", command=lambda:self._select_file(filedialog.askopenfilename()))
        self.text_input = tk.Text(input, width=50, height=10)
        tk.Label(input, text="Name:").grid(row = 1, column = 0, pady=10)
        self.name_input = tk.Entry(input)
        self.name_input.grid(row = 1, column=1)
        tk.Label(input, text="Email:").grid(row = 2, column = 0, pady=10)
        self.email_input = tk.Entry(input)
        self.email_input.grid(row = 2, column=1)
        tk.Label(input, text="If the key is encrypted, enter the password here:", wraplength=150).grid(row = 3, column = 0, pady=10, padx=10)
        self.import_password = tk.Entry(input, show="*")
        self.import_password.grid(row = 3, column=1)
        tk.Label(input, text="Your private key password:", wraplength=150).grid(row=4, column=0,pady=10)
        self.save_password = tk.Entry(input, show = "*")
        self.save_password.grid(row=4,column=1)
        tk.Button(self, text="Import", command=self._import).grid(row=5,column=0,pady=10)
        input.grid(row=2, column=0)
        self._refresh()


    def _select_file(self, value):
        self.selected_file.delete(0, tk.END)
        self.selected_file.insert(0, value)
    
    def _refresh(self):
        if self.file.get():
            self.selected_file.grid(row = 0, column = 1, pady=10)
            self.select_file_button.grid(row = 0, column = 0)
            self.text_input.grid_forget()
        else:
            self.selected_file.grid_forget()
            self.select_file_button.grid_forget()
            self.text_input.grid(row = 0, column = 0, columnspan=2, pady=5)

    def _import(self):
        if self.file.get():
            try:
                with open(self.selected_file.get()) as file:
                    data = file.read()
            except:
                messagebox.showerror("Error", "Couldn't open file. Check the file path or access permission.")
                return
        else: data = self.text_input.get("1.0", "end-1c")
        self.on_import(data, self.name_input.get(), self.email_input.get(), self.import_password.get(), self.save_password.get())

    
"""
Size
Name
Email
Password
"""
class GenerateScreen(tk.Frame):
    def __init__(self, master: tk.Misc, on_generate):
        """
        Args:
            on_generate: A callback method which takes the password, size, name, and email as arguments.
        """
        super().__init__(master)
        self.on_generate = on_generate
        Title(self, "Generate New Key Pair")

        self.big = tk.BooleanVar(value = False)
        selection = tk.Frame(self)
        small = tk.Radiobutton(selection, text = "2048 bit", variable=self.big, value=False)
        big = tk.Radiobutton(selection, text = "4096 bit", variable=self.big, value=True)
        small.grid(row=0, column=0, padx=20, pady=10)
        big.grid(row=0, column=1, padx=20, pady=10)
        selection.grid(row = 1, column = 0)
        self.big.set(True)

        input = tk.Frame(self)
        tk.Label(input, text="Name:").grid(row = 1, column = 0, pady=10)
        self.name_input = tk.Entry(input)
        self.name_input.grid(row = 1, column=1)
        tk.Label(input, text="Email:").grid(row = 2, column = 0, pady=10)
        self.email_input = tk.Entry(input)
        self.email_input.grid(row = 2, column=1)
        tk.Label(input, text="Password:").grid(row=4, column=0,pady=10)
        self.password = tk.Entry(input, show = "*")
        self.password.grid(row=4,column=1)
        tk.Button(self, text="Generate", command=self.generate).grid(row=5,column=0,pady=10)
        input.grid(row=2, column=0)
    def generate(self):
        size = 4096 if self.big.get() else 2048
        name = self.name_input.get()
        email = self.email_input.get()
        password = self.password.get()
        self.on_generate(password, size, name, email)

def big_num_representation(num):
    return hex(num)

class TextInput(tk.Entry):
    def __init__(self, master: tk.Misc, placeholder: str, show: str):
        super().__init__(master)
        self.placeholder = placeholder
        self.show = show
        self.bind('<FocusIn>', self._on_in)
        self.bind('<FocusOut>', self._on_out)
        self._on_out(None)
    def _on_in(self, event):
        if self.get() == self.placeholder:
            self.delete(0, tk.END)
            self.config(fg='black', show=self.show)
    def _on_out(self, event):
        if self.get() == '':
            self.insert(0, self.placeholder)
            self.config(fg='grey', show = None)

"""
    -Public: n, e, export
    -Private: p, q, d, export
"""
class PublicKeyDetailsScreen(tk.Frame):
    def __init__(self, master, key: RSA.RsaKey, on_export):
        """
        Arg:
            on_export: A callback method with no args.
        """
        super().__init__(master)
        Title(self, "Public Key Details")

        data = tk.Frame(self)
        tk.Label(data, text="Modulus (n):").grid(row = 0, column = 0)
        tk.Label(data, text = big_num_representation(key.n), width=70, wraplength=400, bg="white").grid(row = 0, column = 1, pady=10)
        tk.Label(data, text = "Public exponent (e):").grid(row = 1, column = 0)
        tk.Label(data, text= str(key.e)).grid(row = 1, column = 1, pady=10)
        tk.Button(data, text = "Export public key", command=on_export).grid(row = 2 ,column = 0, columnspan=2, pady=10)
        data.grid(row = 1, column=0)

        self._decrypt_frame = tk.Frame(data)
        self.password  = TextInput(self._decrypt_frame, placeholder="Enter password",show="*")
        self.password.grid(row = 0, column = 0)
        tk.Button(self._decrypt_frame, text="Decrypt", command=self._decrypt).grid(row = 0, column = 1)
        self._delete = tk.Button(data, text="Delete key", command=self._delete)
        self.set_on_decrypt(None)
        self.set_on_delete(None)
    
    def set_on_decrypt(self, on_decrypt):
        self.on_decrypt = on_decrypt
        if on_decrypt is None: self._decrypt_frame.grid_forget()
        else: self._decrypt_frame.grid(row = 4, column = 0, columnspan=2, pady=20)
    def set_on_delete(self, on_delete):
        self.on_delete = on_delete
        if on_delete is None: self._delete.grid_forget()
        else: self._delete.grid(row = 5, column = 0, columnspan=2, pady=10)
    
    def _decrypt(self):
        if self.on_decrypt is not None: self.on_decrypt(self.password.get())
    def _delete(self):
        if self.on_delete is None: return
        if messagebox.askokcancel("Delete", "Are sure you want to delete this key?"):
            self.on_delete()


"""
    -Private: p, q, d, export
"""
class PrivateKeyDetailsScreen(tk.Frame):
    def __init__(self, master: tk.Misc, key: RSA.RsaKey, on_export):
        """
        Args:
            on_export: A callback which takes the export password as the only argument.
        """
        super().__init__(master)
        Title(self, "Private Key Details")
        self.on_export = on_export

        data = tk.Frame(self)
        tk.Label(data, text="Prime 1 (p):").grid(row = 0, column = 0)
        tk.Label(data, text = big_num_representation(key.p), width=70, wraplength=400, bg="white").grid(row = 0, column = 1, pady=10)
        tk.Label(data, text = "Prime 2 (q):").grid(row = 1, column = 0)
        tk.Label(data, text= big_num_representation(key.q), width=70, wraplength=400, bg="white").grid(row = 1, column = 1, pady=10)
        tk.Label(data, text = "Private exponent (d):").grid(row = 2, column = 0)
        tk.Label(data, text= big_num_representation(key.q), width=70, wraplength=400, bg="white").grid(row = 2, column = 1, pady=10)
        data.grid(row = 1, column = 0)

        export_frame = tk.Frame(data)
        self._use_pass = tk.BooleanVar(export_frame)
        tk.Checkbutton(export_frame, text="Use password", command=self._change_use_pass, variable=self._use_pass).grid(row = 0, column = 0)
        self._password  = TextInput(export_frame, placeholder="Export password", show="*")
        self._password.grid(row = 0, column = 1)
        tk.Button(export_frame, text="Export private key", command=self._export).grid(row = 0, column = 2)
        export_frame.grid(row = 3, column=0, padx = 20, pady=10, columnspan=2)
        self._change_use_pass()
    
    def _change_use_pass(self):
        use = self._use_pass.get()
        if use: self._password.config(state="normal")
        else: self._password.config(state="disabled")

    def _export(self):
        if self._use_pass.get(): password = self._password.get()
        else: password = None
        self.on_export(password)

class NavigationHost(tk.Frame):
    def __init__(self, master: tk.Misc):
        super().__init__(master)
        self._destinations = []
        self._back = tk.Button(self, text="Back", command=self.back)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
    
    def navigate(self, destination: tk.Frame, sticky="NSEW"):
        if len(self._destinations) > 0:
            self._destinations[-1].grid_forget()
            self._back.grid(row = 0, column = 0, sticky="W")
            destination.grid(row = 1, column = 0, padx=10, pady=5, sticky=sticky)
        else:
            destination.grid(row = 0, column = 0, padx=10, pady=5, sticky=sticky)
        self._destinations.append(destination)
    
    def back(self):
        if len(self._destinations) == 1: return
        self._destinations[-1].destroy()
        self._destinations = self._destinations[:-1]
        if len(self._destinations) == 1:
            self._back.grid_forget()
            self._destinations[-1].grid(row = 0, column = 0, padx=10, pady=5)
        else:
            self._destinations[-1].grid(row = 1, column = 0, padx=10, pady=5)
    
    def cur_destination(self):
        return self._destinations[-1]
        
class PrivateKeysScreen(NavigationHost):
    def __init__(self, master):
        super().__init__(master)
        self._ring = PrivateKeyRing.get_instance()
        self._home = PrivateRingScreen(self, self._ring, self._on_details, self._on_import, self._on_generate)
        self.navigate(self._home)

    def _on_details(self, key: PrivateKeyData):
        self._key = key
        frame = ScrollableFrame(self)
        self._pub = PublicKeyDetailsScreen(frame.get_frame(), key.public, self._on_export_public)
        self._pub.grid(row = 0, column = 0)
        self._pub.set_on_decrypt(self._on_decrypt)
        self.navigate(frame, sticky="NSEW")
        
    def _on_import(self):
        def import_key(pem, name, email, import_pass, save_pass):
            try:
                self._ring.import_key(pem, save_pass, name, email, import_pass)
                messagebox.showinfo("Success", "Key was successfully imported.")
                self._home.refresh()
                self.back()
            except DisplayableException as e:
                messagebox.showerror("Error", str(e))
        self.navigate(ImportPrivateScreen(self, import_key))

    def _on_generate(self):
        def generate(password, size, name, email):
            self._ring.generate_key(password, size, name, email)
            messagebox.showinfo("Success", "A new private key was generated.")
            self._home.refresh()
            self.back()
        self.navigate(GenerateScreen(self, generate))

    def _on_export_public(self):
        file = filedialog.asksaveasfilename()
        if not file: return
        self._key.export(file)
    
    def _on_decrypt(self, password):
        try:
            key = self._key.decode(password)
            self._password = password
            self._pub.set_on_decrypt(None)
            self._pub.set_on_delete(self._on_delete)
            PrivateKeyDetailsScreen(self.cur_destination().get_frame(), key, self._on_export_private).grid(row = 1, column = 0)
        except DisplayableException as e:
            messagebox.showerror("Error", "Incorrect password!")
    
    def _on_delete(self):
        self._key.delete()
        messagebox.showinfo("Success", "The key was successfully deleted.")
        self._key = None
        self._home.refresh()
        self.back()
    
    def _on_export_private(self, password):
        file = filedialog.asksaveasfilename()
        if not file: return
        self._key.export(file, self._password, password)

"""
Table + set trust + add signature
Details + Export
Import
"""
class PublicRingScreen(tk.Frame):
    def __init__(self, master: tk.Misc, ring: PublicKeyRing, on_details, on_import, on_add_signature, on_set_trust):
        """
        Args:
            on_details: A callback which takes the PublicKeyData object as argument.
            on_import: A callback with no arguments.
            on_add_signature: A callback which takes the PublicKeyData and signature email as arguments.
            on_set_trust: A callback which takes the PublicKeyData and trust value as arguments.
        """
        super().__init__(master)
        self._ring = ring
        self._on_details = on_details
        self._on_import = on_import
        self._on_add_signature = on_add_signature
        self._on_set_trust = on_set_trust

        title = Title(self, "Public Key Ring")
        self.table = ScrollTable(self, visible_rows=4, headers=["Timestamp", "Key ID", "Name", "Email", "Owner Trust", "Legit", "Signatures", "Details"])
        self.table.grid(row = 1, column = 0, padx=10, pady=10)

        impor = tk.Button(self, text = "Import", command=self._on_import)
        impor.grid(row = 2, column = 0, ipadx=20, ipady=10)
        
        self.refresh()
        
    
    def refresh(self):
        self.table.set_content(self.get_elem, len(self._ring.get_all()))
    
    def get_elem(self, master, i, j):
        if i >= len(self._ring.get_all()): return None
        key = list(self._ring.get_all().values())[i]
        if j == 0:
            text = datetime.datetime.fromtimestamp(key.timestamp).strftime("%Y-%m-%d %H:%M")
            return tk.Label(master, text = text)
        if j == 1:
            return tk.Label(master, text = key.key_id, width=18)
        if j == 2:
            return tk.Label(master, text = key.name, width=12, wraplength=72)
        if j == 3:
            return tk.Label(master, text = key.email, width=25, wraplength=150)
        if j == 4:
            frame = tk.Frame(master)
            tk.Label(frame, text = str(key.owner_trust), width=4, wraplength=20).pack(side="left")
            tk.Button(frame, text="🖉", command=lambda:self._set_trust(key)).pack(side="left")
            return frame
        if j == 5:
            return tk.Label(master, text="YES" if key.legitimacy else "NO", width=4, wraplength=24)
        if j == 6:
            frame = tk.Frame(master)
            tk.Label(frame, text = "\n".join([sig + " (" + str(self._ring.get_owner_trust(sig)) + ")" for sig in key.signatures]), width=25, wraplength=150).pack(side="top")
            tk.Button(frame, text="🖉", command=lambda:self._add_signature(key)).pack(side="top")
            return frame
        if j == 7:
            return tk.Button(master, text="Details", command=lambda: self._on_details(key))
        raise Exception("Unexpected j value.")
    
    def _set_trust(self, key: PublicKeyData):
        value = simpledialog.askinteger("Change Owner Trust", "Enter owner trust on a scale of 0-100:")
        if value is None: return
        try:
            value = int(value)
            assert(value >= 0 and value <= 100)
        except:
            messagebox.showerror("Error", "Invalid entry.")
            return
        self._on_set_trust(key, value)
    
    def _add_signature(self, key: PublicKeyData):
        value = simpledialog.askstring("Add Signature", "Enter signature email, or * for full trust:")
        if value is None: return
        self._on_add_signature(key, value)
    


    
    
"""
1. File or string
2. Name
3. Email
4. Import password?
5. Save password
"""
class ImportPublicScreen(tk.Frame):
    def __init__(self, master: tk.Misc, on_import):
        """
        Args:
            on_import: A callback method which takes the pem text, name and email as arguments.
        """
        super().__init__(master)
        self.on_import = on_import
        Title(self, "Import Public Key")

        self.file = tk.BooleanVar(value = True)
        selection = tk.Frame(self)
        file = tk.Radiobutton(selection, text = "Import from PEM file", variable=self.file, value=True, command=self._refresh)
        textbox = tk.Radiobutton(selection, text = "Enter the text in PEM format", variable=self.file, value=False, command=self._refresh)
        file.grid(row=0, column=0, padx=20, pady=10)
        textbox.grid(row=0, column=1, padx=20, pady=10)
        selection.grid(row = 1, column = 0)
        self.file.set(True)
        
        input = tk.Frame(self)
        self.selected_file = tk.Entry(input)
        self.select_file_button = tk.Button(input, text = "Select File", command=lambda:self._select_file(filedialog.askopenfilename()))
        self.text_input = tk.Text(input, width=50, height=10)
        tk.Label(input, text="Name:").grid(row = 1, column = 0, pady=10)
        self.name_input = tk.Entry(input)
        self.name_input.grid(row = 1, column=1)
        tk.Label(input, text="Email:").grid(row = 2, column = 0, pady=10)
        self.email_input = tk.Entry(input)
        self.email_input.grid(row = 2, column=1)
        tk.Button(self, text="Import", command=self._import).grid(row=5,column=0,pady=10)
        input.grid(row=2, column=0)
        self._refresh()


    def _select_file(self, value):
        self.selected_file.delete(0, tk.END)
        self.selected_file.insert(0, value)
    
    def _refresh(self):
        if self.file.get():
            self.selected_file.grid(row = 0, column = 1, pady=10)
            self.select_file_button.grid(row = 0, column = 0)
            self.text_input.grid_forget()
        else:
            self.selected_file.grid_forget()
            self.select_file_button.grid_forget()
            self.text_input.grid(row = 0, column = 0, columnspan=2, pady=5)

    def _import(self):
        if self.file.get():
            try:
                with open(self.selected_file.get()) as file:
                    data = file.read()
            except:
                messagebox.showerror("Error", "Couldn't open file. Check the file path or access permission.")
                return
        else: data = self.text_input.get("1.0", "end-1c")
        self.on_import(data, self.name_input.get(), self.email_input.get())
    

class PublicKeysScreen(NavigationHost):
    def __init__(self, master):
        super().__init__(master)
        self._ring = PublicKeyRing.get_instance()
        self._home = PublicRingScreen(self, self._ring, self._on_details, self._on_import, self._on_add_signature, self._on_set_trust)
        self.navigate(self._home)

    def _on_details(self, key: PublicKeyData):
        self._key = key
        frame = ScrollableFrame(self)
        self._pub = PublicKeyDetailsScreen(frame.get_frame(), key.public, self._on_export)
        self._pub.grid(row = 0, column = 0)
        self._pub.set_on_delete(self._on_delete)
        self.navigate(frame, sticky="NSEW")
        
    def _on_import(self):
        def import_key(pem, name, email):
            try:
                self._ring.add_key(pem, name, email)
                messagebox.showinfo("Success", "Key was successfully imported. You can add signatures and set owner trust in the Public Key Ring section.")
                self._home.refresh()
                self.back()
            except DisplayableException as e:
                messagebox.showerror("Error", str(e))
        self.navigate(ImportPublicScreen(self, import_key))

    def _on_export(self):
        file = filedialog.asksaveasfilename()
        if not file: return
        self._key.export(file)
    
    def _on_delete(self):
        self._key.delete()
        messagebox.showinfo("Success", "The key was successfully deleted.")
        self._key = None
        self._home.refresh()
        self.back()
    
    def _on_add_signature(self, key: PublicKeyData, email: str):
        key.add_signature(email)
        self._home.refresh()
    
    def _on_set_trust(self, key: PublicKeyData, value: int):
        self._ring.set_owner_trust(key.email, value)
        self._home.refresh()
    