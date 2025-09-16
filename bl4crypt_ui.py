import tkinter as tk
from tkinter import filedialog, messagebox
import subprocess
import os

UID_FILE = 'saved_uid.txt'
BL4_CRYPT_EXE = 'bl4-crypt-cli'

class BL4CryptApp:
    def ensure_dir(self, path):
        if not os.path.exists(path):
            os.makedirs(path)
    def refresh_decrypt(self):
        self.decrypt_input_files.clear()
        self._decrypt_found_files.clear()
        self.decrypt_files_listbox.delete(0, tk.END)
        self.decrypt_found_listbox.delete(0, tk.END)
        self.update_command_preview()

    def refresh_encrypt(self):
        self.encrypt_input_files.clear()
        self._encrypt_found_files.clear()
        self.encrypt_files_listbox.delete(0, tk.END)
        self.encrypt_found_listbox.delete(0, tk.END)
        self.update_command_preview()
    def save_key_hex(self):
        key = self.key_hex.get().strip()
        if key:
            with open('key.txt', 'w') as f:
                f.write(key)
            messagebox.showinfo('Saved', 'Key hex saved to key.txt!')
        else:
            messagebox.showwarning('Warning', 'Please enter a key hex.')
    def __init__(self, root):
        self.root = root
        self.root.title('BL4 Crypt UI')
        # Encrypt/Decrypt fields
        self.encrypt_input_files = []
        self.decrypt_input_files = []
        # Shared fields
        self.uid = tk.StringVar()
        self.key_hex = tk.StringVar()
        self.key_file = tk.StringVar()
        # Command previews
        self.encrypt_command_preview = tk.StringVar()
        self.decrypt_command_preview = tk.StringVar()
        # Internal found files lists for UI
        self._decrypt_found_files = []
        self._encrypt_found_files = []
        # Auto-create input/output folders on startup
        for folder in [
            'input_encrypt', 'input_decrypt', 'output_encrypt', 'output_decrypt']:
            self.ensure_dir(os.path.join(os.getcwd(), folder))
        self.load_uid()
        self.create_widgets()
        # Auto-populate found files from input folders
        self.auto_populate_found_files()

    def auto_populate_found_files(self):
        # Populate encrypt found files from input_encrypt
        encrypt_dir = os.path.join(os.getcwd(), 'input_encrypt')
        encrypt_files = [os.path.join(encrypt_dir, f) for f in os.listdir(encrypt_dir) if f.lower().endswith('.yaml')]
        self._encrypt_found_files = encrypt_files
        self.encrypt_found_listbox.delete(0, tk.END)
        for f in encrypt_files:
            self.encrypt_found_listbox.insert(tk.END, os.path.basename(f))
        # Populate decrypt found files from input_decrypt
        decrypt_dir = os.path.join(os.getcwd(), 'input_decrypt')
        decrypt_files = [os.path.join(decrypt_dir, f) for f in os.listdir(decrypt_dir) if f.lower().endswith('.sav')]
        self._decrypt_found_files = decrypt_files
        self.decrypt_found_listbox.delete(0, tk.END)
        for f in decrypt_files:
            self.decrypt_found_listbox.insert(tk.END, os.path.basename(f))

    def create_widgets(self):
        # Decrypt Section
        decrypt_frame = tk.LabelFrame(self.root, text='Decrypt', padx=10, pady=10)
        decrypt_frame.grid(row=0, column=0, padx=10, pady=5, sticky='ew')
        # Found Files Listbox for decrypt
        tk.Label(decrypt_frame, text='Found Files (.sav):').grid(row=0, column=0, sticky='ne')
        self.decrypt_found_listbox = tk.Listbox(decrypt_frame, selectmode='browse', width=30, height=4)
        self.decrypt_found_listbox.grid(row=0, column=1, sticky='ew')
        tk.Button(decrypt_frame, text='Scan Dir', command=self.scan_decrypt_dirs).grid(row=0, column=2)
        # Files to be changed Listbox for decrypt
        tk.Label(decrypt_frame, text='Files to be changed:').grid(row=1, column=0, sticky='ne')
        self.decrypt_files_listbox = tk.Listbox(decrypt_frame, selectmode='extended', width=30, height=4)
        self.decrypt_files_listbox.grid(row=1, column=1, sticky='ew')
        # Double-click to add from found to change
        self.decrypt_found_listbox.bind('<Double-Button-1>', lambda e: self.move_found_to_change('decrypt'))
        # Double-click to remove from change list
        # Double-click to add from found to change
        self.encrypt_found_listbox.bind('<Double-Button-1>', lambda e: self.move_found_to_change('encrypt'))
        # Double-click to remove from change list
        self.encrypt_files_listbox.bind('<Double-Button-1>', lambda e: self.move_change_to_found('encrypt'))
    # Decrypt command preview
    # Decrypt command preview
    def scan_decrypt_dirs(self):
        self.decrypt_found_listbox.delete(0, tk.END)
        decrypt_dir = os.path.join(os.getcwd(), 'input_decrypt')
        files = [os.path.join(decrypt_dir, f) for f in os.listdir(decrypt_dir) if f.lower().endswith('.sav')]
        files = [f for f in files if f not in self.decrypt_input_files]
        self._decrypt_found_files = files
        for f in files:
            self.decrypt_found_listbox.insert(tk.END, os.path.basename(f))

    def scan_encrypt_dirs(self):
        self.encrypt_found_listbox.delete(0, tk.END)
        encrypt_dir = os.path.join(os.getcwd(), 'input_encrypt')
        files = [os.path.join(encrypt_dir, f) for f in os.listdir(encrypt_dir) if f.lower().endswith('.yaml')]
        files = [f for f in files if f not in self.encrypt_input_files]
        self._encrypt_found_files = files
        for f in files:
            self.encrypt_found_listbox.insert(tk.END, os.path.basename(f))

    def move_found_to_change(self, mode):
        if mode == 'decrypt':
            sel = self.decrypt_found_listbox.curselection()
            if not sel:
                return
            idx = sel[0]
            fname = self._decrypt_found_files[idx]
            if fname not in self.decrypt_input_files:
                self.decrypt_input_files.append(fname)
                self.decrypt_files_listbox.insert(tk.END, os.path.basename(fname))
            self.decrypt_found_listbox.delete(idx)
            self._decrypt_found_files.pop(idx)
        else:
            sel = self.encrypt_found_listbox.curselection()
            if not sel:
                return
            idx = sel[0]
            fname = self._encrypt_found_files[idx]
            if fname not in self.encrypt_input_files:
                self.encrypt_input_files.append(fname)
                self.encrypt_files_listbox.insert(tk.END, os.path.basename(fname))
            self.encrypt_found_listbox.delete(idx)
            self._encrypt_found_files.pop(idx)
        self.update_command_preview()

    def move_change_to_found(self, mode):
        if mode == 'decrypt':
            sel = self.decrypt_files_listbox.curselection()
            for idx in reversed(sel):
                fname = self.decrypt_files_listbox.get(idx)
                full = [f for f in self.decrypt_input_files if os.path.basename(f) == fname]
                if full:
                    self.decrypt_input_files.remove(full[0])
                    self._decrypt_found_files.append(full[0])
                    self.decrypt_found_listbox.insert(tk.END, fname)
                self.decrypt_files_listbox.delete(idx)
        else:
            sel = self.encrypt_files_listbox.curselection()
            for idx in reversed(sel):
                fname = self.encrypt_files_listbox.get(idx)
                full = [f for f in self.encrypt_input_files if os.path.basename(f) == fname]
                if full:
                    self.encrypt_input_files.remove(full[0])
                    self._encrypt_found_files.append(full[0])
                    self.encrypt_found_listbox.insert(tk.END, fname)
                self.encrypt_files_listbox.delete(idx)
        self.update_command_preview()
    def show_files_window(self, mode):
        win = tk.Toplevel(self.root)
        win.title(f"{mode.capitalize()} - Files to be changed")
        win.geometry("900x700")

        # Use frames to control layout and force size
        found_frame = tk.Frame(win, width=800, height=250)
        found_frame.pack(fill='both', expand=True)
        found_frame.pack_propagate(False)
        found_label = tk.Label(found_frame, text="Found Files (double-click to add):")
        found_label.pack(anchor='w')
        found_listbox = tk.Listbox(found_frame, selectmode='browse', width=120, height=20)
        found_listbox.pack(fill='both', expand=True)

        change_frame = tk.Frame(win, width=800, height=250)
        change_frame.pack(fill='both', expand=True)
        change_frame.pack_propagate(False)
        change_label = tk.Label(change_frame, text="Files to be changed:")
        change_label.pack(anchor='w')
        change_listbox = tk.Listbox(change_frame, selectmode='extended', width=120, height=20)
        change_listbox.pack(fill='both', expand=True)

        # Populate found_listbox with current directory scan
        if mode == 'encrypt':
            files = [os.path.join(os.getcwd(), 'input_encrypt', f) for f in os.listdir(os.path.join(os.getcwd(), 'input_encrypt')) if f.lower().endswith('.yaml')]
            files = [f for f in files if f not in self.encrypt_input_files]
        else:
            files = [os.path.join(os.getcwd(), 'input_decrypt', f) for f in os.listdir(os.path.join(os.getcwd(), 'input_decrypt')) if f.lower().endswith('.sav')]
            files = [f for f in files if f not in self.decrypt_input_files]
        for f in files:
            found_listbox.insert(tk.END, os.path.basename(f))
        # Populate change_listbox with current to-be-changed files
        if mode == 'encrypt':
            for f in self.encrypt_input_files:
                change_listbox.insert(tk.END, os.path.basename(f))
        else:
            for f in self.decrypt_input_files:
                change_listbox.insert(tk.END, os.path.basename(f))
        # Double-click to move from found to change
        def add_file(event=None):
            sel = found_listbox.curselection()
            if not sel:
                return
            idx = sel[0]
            fname = files[idx]
            if mode == 'encrypt':
                if fname not in self.encrypt_input_files:
                    self.encrypt_input_files.append(fname)
                    change_listbox.insert(tk.END, os.path.basename(fname))
            else:
                if fname not in self.decrypt_input_files:
                    self.decrypt_input_files.append(fname)
                    change_listbox.insert(tk.END, os.path.basename(fname))
            found_listbox.delete(idx)
            files.pop(idx)
            self.update_command_preview()
        found_listbox.bind('<Double-Button-1>', add_file)
        # Remove button to move back to found
        def remove_file():
            sel = list(change_listbox.curselection())
            for idx in reversed(sel):
                fname = change_listbox.get(idx)
                # Find full path
                if mode == 'encrypt':
                    full = [f for f in self.encrypt_input_files if os.path.basename(f) == fname]
                    if full:
                        self.encrypt_input_files.remove(full[0])
                        found_listbox.insert(tk.END, fname)
                        files.append(full[0])
                else:
                    full = [f for f in self.decrypt_input_files if os.path.basename(f) == fname]
                    if full:
                        self.decrypt_input_files.remove(full[0])
                        found_listbox.insert(tk.END, fname)
                        files.append(full[0])
                change_listbox.delete(idx)
            self.update_command_preview()
        if mode == 'encrypt':
            for f in self.encrypt_input_files:
                change_listbox.insert(tk.END, os.path.basename(f))
        else:
            for f in self.decrypt_input_files:
                change_listbox.insert(tk.END, os.path.basename(f))
        # Double-click to move from found to change
        def add_file(event=None):
            sel = found_listbox.curselection()
            if not sel:
                return
            idx = sel[0]
            fname = files[idx]
            if mode == 'encrypt':
                if fname not in self.encrypt_input_files:
                    self.encrypt_input_files.append(fname)
                    change_listbox.insert(tk.END, os.path.basename(fname))
            else:
                if fname not in self.decrypt_input_files:
                    self.decrypt_input_files.append(fname)
                    change_listbox.insert(tk.END, os.path.basename(fname))
            found_listbox.delete(idx)
            files.pop(idx)
            self.update_command_preview()
        found_listbox.bind('<Double-Button-1>', add_file)
        # Remove button to move back to found
        def remove_file():
            sel = list(change_listbox.curselection())
            for idx in reversed(sel):
                fname = change_listbox.get(idx)
                # Find full path
                if mode == 'encrypt':
                    full = [f for f in self.encrypt_input_files if os.path.basename(f) == fname]
                    if full:
                        self.encrypt_input_files.remove(full[0])
                        found_listbox.insert(tk.END, fname)
                        files.append(full[0])
                else:
                    full = [f for f in self.decrypt_input_files if os.path.basename(f) == fname]
                    if full:
                        self.decrypt_input_files.remove(full[0])
                        found_listbox.insert(tk.END, fname)
                        files.append(full[0])
                change_listbox.delete(idx)
            self.update_command_preview()
        tk.Button(win, text="Remove from change list", command=remove_file).pack(pady=5)
        tk.Button(win, text="Done", command=win.destroy).pack(pady=5)
    def add_encrypt_files(self):
        files = filedialog.askopenfilenames(filetypes=[('All files', '*.*')])
        for f in files:
            if f not in self.encrypt_input_files:
                self.encrypt_input_files.append(f)
                self.encrypt_files_listbox.insert(tk.END, os.path.basename(f))
        self.update_command_preview()

    def create_widgets(self):
        # Decrypt Section
        decrypt_frame = tk.LabelFrame(self.root, text='Decrypt', padx=10, pady=10)
        decrypt_frame.grid(row=0, column=0, padx=10, pady=5, sticky='ew')
        # Found Files Listbox for decrypt
        tk.Label(decrypt_frame, text='Found Files (.sav):').grid(row=0, column=0, sticky='ne')
        self.decrypt_found_listbox = tk.Listbox(decrypt_frame, selectmode='browse', width=30, height=4)
        self.decrypt_found_listbox.grid(row=0, column=1, sticky='ew')
        tk.Button(decrypt_frame, text='Scan Dir', command=self.scan_decrypt_dirs).grid(row=0, column=2)
        # Files to be changed Listbox for decrypt
        tk.Label(decrypt_frame, text='Files to be changed:').grid(row=1, column=0, sticky='ne')
        self.decrypt_files_listbox = tk.Listbox(decrypt_frame, selectmode='extended', width=30, height=4)
        self.decrypt_files_listbox.grid(row=1, column=1, sticky='ew')
        # Double-click to add from found to change
        self.decrypt_found_listbox.bind('<Double-Button-1>', lambda e: self.move_found_to_change('decrypt'))
        # Double-click to remove from change list
        self.decrypt_files_listbox.bind('<Double-Button-1>', lambda e: self.move_change_to_found('decrypt'))
        # Removed input/output directory UI for decrypt
        tk.Button(decrypt_frame, text='Decrypt', command=self.decrypt_file).grid(row=5, column=1, pady=10)
        tk.Button(decrypt_frame, text='Refresh', command=self.refresh_decrypt).grid(row=5, column=2, pady=10)

        # Encrypt Section
        encrypt_frame = tk.LabelFrame(self.root, text='Encrypt', padx=10, pady=10)
        encrypt_frame.grid(row=0, column=1, padx=10, pady=5, sticky='ew')
        # Found Files Listbox for encrypt
        tk.Label(encrypt_frame, text='Found Files (.yaml):').grid(row=0, column=0, sticky='ne')
        self.encrypt_found_listbox = tk.Listbox(encrypt_frame, selectmode='browse', width=30, height=4)
        self.encrypt_found_listbox.grid(row=0, column=1, sticky='ew')
        tk.Button(encrypt_frame, text='Scan Dir', command=self.scan_encrypt_dirs).grid(row=0, column=2)
        # Files to be changed Listbox for encrypt
        tk.Label(encrypt_frame, text='Files to be changed:').grid(row=1, column=0, sticky='ne')
        self.encrypt_files_listbox = tk.Listbox(encrypt_frame, selectmode='extended', width=30, height=4)
        self.encrypt_files_listbox.grid(row=1, column=1, sticky='ew')
        # Double-click to add from found to change
        self.encrypt_found_listbox.bind('<Double-Button-1>', lambda e: self.move_found_to_change('encrypt'))
        # Double-click to remove from change list
        self.encrypt_files_listbox.bind('<Double-Button-1>', lambda e: self.move_change_to_found('encrypt'))
    # Removed input directory UI for encrypt
        tk.Button(encrypt_frame, text='Encrypt', command=self.encrypt_file).grid(row=5, column=1, pady=10)
        tk.Button(encrypt_frame, text='Refresh', command=self.refresh_encrypt).grid(row=5, column=2, pady=10)

        # Decrypt command preview
        decrypt_preview_frame = tk.Frame(self.root)
        decrypt_preview_frame.grid(row=2, column=0, pady=5, sticky='ew')
        tk.Label(decrypt_preview_frame, text='Decrypt Command Preview:').grid(row=0, column=0, sticky='w')
        tk.Entry(decrypt_preview_frame, textvariable=self.decrypt_command_preview, width=80, state='readonly').grid(row=0, column=1, sticky='ew')

        # Encrypt command preview
        encrypt_preview_frame = tk.Frame(self.root)
        encrypt_preview_frame.grid(row=2, column=1, pady=5, sticky='ew')
        tk.Label(encrypt_preview_frame, text='Encrypt Command Preview:').grid(row=0, column=0, sticky='w')
        tk.Entry(encrypt_preview_frame, textvariable=self.encrypt_command_preview, width=80, state='readonly').grid(row=0, column=1, sticky='ew')

        # Shared fields (SteamID64, Key)
        shared_frame = tk.Frame(self.root)
        shared_frame.grid(row=3, column=0, columnspan=2, pady=10, sticky='ew')
        tk.Label(shared_frame, text='Steam UID:').grid(row=0, column=0, sticky='e')
        tk.Entry(shared_frame, textvariable=self.uid, width=40).grid(row=0, column=1)
        tk.Button(shared_frame, text='Save UID', command=self.save_uid).grid(row=0, column=2)
        tk.Label(shared_frame, text='Key (hex):').grid(row=1, column=0, sticky='e')
        tk.Entry(shared_frame, textvariable=self.key_hex, width=40).grid(row=1, column=1)
        tk.Button(shared_frame, text='Save Key Hex', command=self.save_key_hex).grid(row=1, column=2)
        tk.Label(shared_frame, text='Key File:').grid(row=2, column=0, sticky='e')
        tk.Entry(shared_frame, textvariable=self.key_file, width=40, state='readonly').grid(row=2, column=1)
        tk.Button(shared_frame, text='Browse Key File', command=self.browse_key_file).grid(row=2, column=2)



    # --- Browsing helpers for encrypt/decrypt ---
    def browse_encrypt_files(self):
        files = filedialog.askopenfilenames(filetypes=[('All files', '*.*')])
        if files:
            self.encrypt_input_files = list(files)
            self.encrypt_input_files_var.set('; '.join(self.encrypt_input_files))
            self.update_command_preview()

    def browse_encrypt_dirs(self):
        pass  # Removed

    def browse_encrypt_output_dir(self):
        pass  # Removed

    def browse_decrypt_files(self):
        files = filedialog.askopenfilenames(filetypes=[('All files', '*.*')])
        if files:
            self.decrypt_input_files = list(files)
            self.decrypt_input_files_var.set('; '.join(self.decrypt_input_files))
            self.update_command_preview()

    def browse_decrypt_dirs(self):
        pass  # Removed

    def browse_decrypt_output_dir(self):
        pass  # Removed

    def browse_input_dir(self):
        dir_ = filedialog.askdirectory()
        if dir_:
            self.input_dir.set(dir_)

    def browse_output_dir(self):
        dir_ = filedialog.askdirectory()
        if dir_:
            self.output_dir.set(dir_)

    def browse_key_file(self):
        file = filedialog.askopenfilename(filetypes=[('All files', '*.*')])
        if file:
            self.key_file.set(file)

    def save_uid(self):
        uid = self.uid.get().strip()
        if uid:
            with open(UID_FILE, 'w') as f:
                f.write(uid)
            messagebox.showinfo('Saved', 'Steam UID saved!')
        else:
            messagebox.showwarning('Warning', 'Please enter a Steam UID.')

    def load_uid(self):
        if os.path.exists(UID_FILE):
            with open(UID_FILE, 'r') as f:
                self.uid.set(f.read().strip())

    def decrypt_file(self):
        output_dir = os.path.join(os.getcwd(), 'output_decrypt')
        self.ensure_dir(output_dir)
        # If no input files, warn
        if not self.decrypt_input_files:
            messagebox.showwarning('Warning', 'Please select input files.')
            return
        # Run command for each file individually
        errors = []
        for f in self.decrypt_input_files:
            base = os.path.splitext(os.path.basename(f))[0]
            out_file = os.path.join(output_dir, base + '.yaml')
            cmd = [BL4_CRYPT_EXE, 'decrypt', '-i', f, '-o', out_file]
            if self.uid.get().strip():
                cmd += ['-s', self.uid.get().strip()]
            key_hex_val = self.key_hex.get().strip()
            key_file_val = self.key_file.get().strip()
            if key_hex_val:
                cmd += ['-h', key_hex_val]
            elif key_file_val:
                cmd += ['-f', key_file_val]
            try:
                self.run_cmd(cmd, None)
            except Exception as e:
                errors.append(f"{os.path.basename(f)}: {e}")
        if len(self.decrypt_input_files) > 1:
            if errors:
                messagebox.showerror('Error', 'Some files failed to decrypt:\n' + '\n'.join(errors))
            else:
                messagebox.showinfo('Success', 'All files decrypted successfully.')
        elif self.decrypt_input_files:
            if errors:
                messagebox.showerror('Error', f'Failed to decrypt {os.path.basename(self.decrypt_input_files[0])}: {errors[0]}')
            else:
                messagebox.showinfo('Success', f'Decryption complete for {os.path.basename(self.decrypt_input_files[0])}.')
        self.update_command_preview()

    def encrypt_file(self):
        output_dir = os.path.join(os.getcwd(), 'output_encrypt')
        self.ensure_dir(output_dir)
        # If no input files, warn
        if not self.encrypt_input_files:
            messagebox.showwarning('Warning', 'Please select input files.')
            return
        # Run command for each file individually
        errors = []
        for f in self.encrypt_input_files:
            base = os.path.splitext(os.path.basename(f))[0]
            out_file = os.path.join(output_dir, base + '.sav')
            cmd = [BL4_CRYPT_EXE, 'encrypt', '-i', f, '-o', out_file]
            if self.uid.get().strip():
                cmd += ['-s', self.uid.get().strip()]
            if self.key_hex.get().strip():
                cmd += ['-h', self.key_hex.get().strip()]
            elif self.key_file.get().strip():
                cmd += ['-f', self.key_file.get().strip()]
            try:
                self.run_cmd(cmd, None)
            except Exception as e:
                errors.append(f"{os.path.basename(f)}: {e}")
        if len(self.encrypt_input_files) > 1:
            if errors:
                messagebox.showerror('Error', 'Some files failed to encrypt:\n' + '\n'.join(errors))
            else:
                messagebox.showinfo('Success', 'All files encrypted successfully.')
        elif self.encrypt_input_files:
            if errors:
                messagebox.showerror('Error', f'Failed to encrypt {os.path.basename(self.encrypt_input_files[0])}: {errors[0]}')
            else:
                messagebox.showinfo('Success', f'Encryption complete for {os.path.basename(self.encrypt_input_files[0])}.')
        self.update_command_preview()

    def update_command_preview(self):
        # Encrypt command preview
        enc_cmd = [BL4_CRYPT_EXE, 'encrypt']
        for f in self.encrypt_input_files:
            enc_cmd += ['-i', f]
        enc_cmd += ['-d', os.path.join(os.getcwd(), 'output_encrypt')]
        if self.uid.get().strip():
            enc_cmd += ['-s', self.uid.get().strip()]
        if self.key_hex.get().strip():
            enc_cmd += ['-h', self.key_hex.get().strip()]
        if self.key_file.get().strip():
            enc_cmd += ['-f', self.key_file.get().strip()]
        self.encrypt_command_preview.set(' '.join(f'"{c}"' if ' ' in c else c for c in enc_cmd))

        # Decrypt command preview
        dec_cmd = [BL4_CRYPT_EXE, 'decrypt']
        for f in self.decrypt_input_files:
            dec_cmd += ['-i', f]
        dec_cmd += ['-d', os.path.join(os.getcwd(), 'output_decrypt')]
        if self.uid.get().strip():
            dec_cmd += ['-s', self.uid.get().strip()]
        if self.key_hex.get().strip():
            dec_cmd += ['-h', self.key_hex.get().strip()]
        if self.key_file.get().strip():
            dec_cmd += ['-f', self.key_file.get().strip()]
        self.decrypt_command_preview.set(' '.join(f'"{c}"' if ' ' in c else c for c in dec_cmd))

    def run_cmd(self, cmd, success_msg):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            if success_msg:
                messagebox.showinfo('Success', success_msg)
        except subprocess.CalledProcessError as e:
            raise Exception(e.stderr.strip() or str(e))

if __name__ == '__main__':
    root = tk.Tk()
    app = BL4CryptApp(root)
    root.mainloop()
