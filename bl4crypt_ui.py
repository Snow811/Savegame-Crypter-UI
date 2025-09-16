import tkinter as tk
from tkinter import filedialog, messagebox
import subprocess
import os

UID_FILE = 'saved_uid.txt'
BL4_CRYPT_EXE = 'bl4-crypt.exe'

class BL4CryptApp:
    def __init__(self, root):
        self.root = root
        self.root.title('BL4 Crypt UI')
        self.file_path = tk.StringVar()
        self.uid = tk.StringVar()
        self.load_uid()
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.root, text='Input File:').grid(row=0, column=0, sticky='e')
        tk.Entry(self.root, textvariable=self.file_path, width=40).grid(row=0, column=1)
        tk.Button(self.root, text='Browse', command=self.browse_file).grid(row=0, column=2)

        tk.Label(self.root, text='Output Filename:').grid(row=1, column=0, sticky='e')
        self.output_path = tk.StringVar()
        tk.Entry(self.root, textvariable=self.output_path, width=40).grid(row=1, column=1)

        tk.Label(self.root, text='Steam UID:').grid(row=2, column=0, sticky='e')
        tk.Entry(self.root, textvariable=self.uid, width=40).grid(row=2, column=1)
        tk.Button(self.root, text='Save UID', command=self.save_uid).grid(row=2, column=2)

        tk.Button(self.root, text='Decrypt', command=self.decrypt_file).grid(row=3, column=0, pady=10)
        tk.Button(self.root, text='Encrypt', command=self.encrypt_file).grid(row=3, column=1, pady=10)



    def browse_file(self):
        file = filedialog.askopenfilename(filetypes=[('SAV files', '*.sav'), ('All files', '*.*')])
        if file:
            self.file_path.set(file)

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
        file = self.file_path.get().strip()
        uid = self.uid.get().strip()
        if not file or not uid:
            messagebox.showwarning('Warning', 'Please select an input file and enter a Steam UID.')
            return
        file_name = os.path.basename(file)
        output = self.output_path.get().strip()
        if not output:
            output = os.path.splitext(file_name)[0] + '.yaml'
        if not output.lower().endswith('.yaml'):
            output += '.yaml'
            self.output_path.set(output)
        cmd = [BL4_CRYPT_EXE, 'decrypt', '-i', file_name, '-o', output, '-u', uid]
        self.run_cmd(cmd, f'Decrypted to {output}')

    def encrypt_file(self):
        file = self.file_path.get().strip()
        uid = self.uid.get().strip()
        if not file or not uid:
            messagebox.showwarning('Warning', 'Please select an input file and enter a Steam UID.')
            return
        file_name = os.path.basename(file)
        output = self.output_path.get().strip()
        if not output:
            output = os.path.splitext(file_name)[0] + '.sav'
        if not output.lower().endswith('.sav'):
            output += '.sav'
            self.output_path.set(output)
        cmd = [BL4_CRYPT_EXE, 'encrypt', '-i', file_name, '-o', output, '-u', uid]
        self.run_cmd(cmd, f'Encrypted to {output}')

    def run_cmd(self, cmd, success_msg):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            messagebox.showinfo('Success', success_msg)
        except subprocess.CalledProcessError as e:
            messagebox.showerror('Error', f'Command failed:\n{e.stderr}')

if __name__ == '__main__':
    root = tk.Tk()
    app = BL4CryptApp(root)
    root.mainloop()
