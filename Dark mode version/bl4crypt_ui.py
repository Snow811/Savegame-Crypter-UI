import sys
import os
import subprocess
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QGridLayout, QGroupBox, QListWidget, 
                             QLineEdit, QPushButton, QLabel, QFileDialog, 
                             QMessageBox, QFrame, QSplitter, QTextEdit)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont, QPalette, QColor

UID_FILE = 'saved_uid.txt'
BL4_CRYPT_EXE = 'bl4-crypt-cli'

# Dark theme stylesheet
DARK_THEME = """
QMainWindow {
    background-color: #2b2b2b;
    color: #ffffff;
}

QWidget {
    background-color: #2b2b2b;
    color: #ffffff;
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 9pt;
}

QGroupBox {
    font-weight: bold;
    border: 2px solid #555555;
    border-radius: 8px;
    margin-top: 10px;
    padding-top: 10px;
    background-color: #3c3c3c;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 8px 0 8px;
    color: #ffffff;
    font-size: 10pt;
}

QPushButton {
    background-color: #0078d4;
    color: white;
    border: none;
    padding: 8px 16px;
    border-radius: 4px;
    font-weight: bold;
    min-width: 80px;
}

QPushButton:hover {
    background-color: #106ebe;
}

QPushButton:pressed {
    background-color: #005a9e;
}

QPushButton:disabled {
    background-color: #555555;
    color: #888888;
}

QLineEdit {
    background-color: #404040;
    border: 1px solid #555555;
    padding: 6px;
    border-radius: 4px;
    color: #ffffff;
}

QLineEdit:focus {
    border: 2px solid #0078d4;
}

QLineEdit:read-only {
    background-color: #333333;
    color: #cccccc;
}

QListWidget {
    background-color: #404040;
    border: 1px solid #555555;
    border-radius: 4px;
    alternate-background-color: #484848;
    selection-background-color: #0078d4;
    selection-color: white;
}

QListWidget::item {
    padding: 4px;
    border-bottom: 1px solid #555555;
}

QListWidget::item:hover {
    background-color: #505050;
}

QListWidget::item:selected {
    background-color: #0078d4;
}

QLabel {
    color: #ffffff;
    padding: 2px;
}

QTextEdit {
    background-color: #404040;
    border: 1px solid #555555;
    border-radius: 4px;
    color: #ffffff;
    font-family: 'Consolas', 'Courier New', monospace;
}

QFrame {
    background-color: #2b2b2b;
}

QSplitter::handle {
    background-color: #555555;
}

QSplitter::handle:horizontal {
    width: 3px;
}

QSplitter::handle:vertical {
    height: 3px;
}

/* Scrollbars */
QScrollBar:vertical {
    background-color: #2b2b2b;
    width: 12px;
    border-radius: 6px;
}

QScrollBar::handle:vertical {
    background-color: #555555;
    border-radius: 6px;
    min-height: 20px;
}

QScrollBar::handle:vertical:hover {
    background-color: #666666;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    background-color: #2b2b2b;
    height: 12px;
    border-radius: 6px;
}

QScrollBar::handle:horizontal {
    background-color: #555555;
    border-radius: 6px;
    min-width: 20px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #666666;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}
"""

class BL4CryptApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('BL4 Crypt UI - Dark Edition')
        self.setGeometry(100, 100, 1200, 800)
        
        # Data storage
        self.encrypt_input_files = []
        self.decrypt_input_files = []
        self._decrypt_found_files = []
        self._encrypt_found_files = []
        
        # Auto-create input/output folders on startup
        for folder in ['input_encrypt', 'input_decrypt', 'output_encrypt', 'output_decrypt']:
            self.ensure_dir(os.path.join(os.getcwd(), folder))
        
        # Load saved UID
        self.load_uid()
        
        # Setup UI
        self.setup_ui()
        self.auto_populate_found_files()
        self.update_command_preview()

    def ensure_dir(self, path):
        if not os.path.exists(path):
            os.makedirs(path)

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(15, 15, 15, 15)
        
        # Create main splitter for encrypt/decrypt sections
        splitter = QSplitter(Qt.Horizontal)
        main_layout.addWidget(splitter)
        
        # Decrypt section
        decrypt_group = self.create_decrypt_section()
        splitter.addWidget(decrypt_group)
        
        # Encrypt section
        encrypt_group = self.create_encrypt_section()
        splitter.addWidget(encrypt_group)
        
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)
        
        # Command preview section
        preview_frame = self.create_preview_section()
        main_layout.addWidget(preview_frame)
        
        # Shared settings section
        settings_frame = self.create_settings_section()
        main_layout.addWidget(settings_frame)

    def create_decrypt_section(self):
        decrypt_group = QGroupBox("Decrypt")
        layout = QVBoxLayout(decrypt_group)
        
        # Found files section
        found_layout = QHBoxLayout()
        found_layout.addWidget(QLabel("Found Files (.sav):"))
        self.decrypt_found_listbox = QListWidget()
        self.decrypt_found_listbox.setMaximumHeight(120)
        found_layout.addWidget(self.decrypt_found_listbox)
        scan_decrypt_btn = QPushButton("Scan Dir")
        scan_decrypt_btn.clicked.connect(self.scan_decrypt_dirs)
        found_layout.addWidget(scan_decrypt_btn)
        layout.addLayout(found_layout)
        
        # Files to be changed section
        change_layout = QHBoxLayout()
        change_layout.addWidget(QLabel("Files to be changed:"))
        self.decrypt_files_listbox = QListWidget()
        self.decrypt_files_listbox.setMaximumHeight(120)
        change_layout.addWidget(self.decrypt_files_listbox)
        layout.addLayout(change_layout)
        
        # Action buttons
        button_layout = QHBoxLayout()
        decrypt_btn = QPushButton("Decrypt")
        decrypt_btn.clicked.connect(self.decrypt_file)
        refresh_decrypt_btn = QPushButton("Refresh")
        refresh_decrypt_btn.clicked.connect(self.refresh_decrypt)
        button_layout.addWidget(decrypt_btn)
        button_layout.addWidget(refresh_decrypt_btn)
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        # Connect double-click events
        self.decrypt_found_listbox.itemDoubleClicked.connect(
            lambda: self.move_found_to_change('decrypt'))
        self.decrypt_files_listbox.itemDoubleClicked.connect(
            lambda: self.move_change_to_found('decrypt'))
        
        return decrypt_group

    def create_encrypt_section(self):
        encrypt_group = QGroupBox("Encrypt")
        layout = QVBoxLayout(encrypt_group)
        
        # Found files section
        found_layout = QHBoxLayout()
        found_layout.addWidget(QLabel("Found Files (.yaml):"))
        self.encrypt_found_listbox = QListWidget()
        self.encrypt_found_listbox.setMaximumHeight(120)
        found_layout.addWidget(self.encrypt_found_listbox)
        scan_encrypt_btn = QPushButton("Scan Dir")
        scan_encrypt_btn.clicked.connect(self.scan_encrypt_dirs)
        found_layout.addWidget(scan_encrypt_btn)
        layout.addLayout(found_layout)
        
        # Files to be changed section
        change_layout = QHBoxLayout()
        change_layout.addWidget(QLabel("Files to be changed:"))
        self.encrypt_files_listbox = QListWidget()
        self.encrypt_files_listbox.setMaximumHeight(120)
        change_layout.addWidget(self.encrypt_files_listbox)
        layout.addLayout(change_layout)
        
        # Action buttons
        button_layout = QHBoxLayout()
        encrypt_btn = QPushButton("Encrypt")
        encrypt_btn.clicked.connect(self.encrypt_file)
        refresh_encrypt_btn = QPushButton("Refresh")
        refresh_encrypt_btn.clicked.connect(self.refresh_encrypt)
        button_layout.addWidget(encrypt_btn)
        button_layout.addWidget(refresh_encrypt_btn)
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        # Connect double-click events
        self.encrypt_found_listbox.itemDoubleClicked.connect(
            lambda: self.move_found_to_change('encrypt'))
        self.encrypt_files_listbox.itemDoubleClicked.connect(
            lambda: self.move_change_to_found('encrypt'))
        
        return encrypt_group

    def create_preview_section(self):
        preview_group = QGroupBox("Command Preview")
        layout = QVBoxLayout(preview_group)
        
        # Decrypt command preview
        decrypt_preview_layout = QHBoxLayout()
        decrypt_preview_layout.addWidget(QLabel("Decrypt Command:"))
        self.decrypt_command_preview = QLineEdit()
        self.decrypt_command_preview.setReadOnly(True)
        decrypt_preview_layout.addWidget(self.decrypt_command_preview)
        layout.addLayout(decrypt_preview_layout)
        
        # Encrypt command preview
        encrypt_preview_layout = QHBoxLayout()
        encrypt_preview_layout.addWidget(QLabel("Encrypt Command:"))
        self.encrypt_command_preview = QLineEdit()
        self.encrypt_command_preview.setReadOnly(True)
        encrypt_preview_layout.addWidget(self.encrypt_command_preview)
        layout.addLayout(encrypt_preview_layout)
        
        return preview_group

    def create_settings_section(self):
        settings_group = QGroupBox("Settings")
        layout = QGridLayout(settings_group)
        
        # Steam UID
        layout.addWidget(QLabel("Steam UID:"), 0, 0)
        self.uid_entry = QLineEdit()
        layout.addWidget(self.uid_entry, 0, 1)
        save_uid_btn = QPushButton("Save UID")
        save_uid_btn.clicked.connect(self.save_uid)
        layout.addWidget(save_uid_btn, 0, 2)
        
        # Key hex
        layout.addWidget(QLabel("Key (hex):"), 1, 0)
        self.key_hex_entry = QLineEdit()
        layout.addWidget(self.key_hex_entry, 1, 1)
        save_key_btn = QPushButton("Save Key Hex")
        save_key_btn.clicked.connect(self.save_key_hex)
        layout.addWidget(save_key_btn, 1, 2)
        
        # Key file
        layout.addWidget(QLabel("Key File:"), 2, 0)
        self.key_file_entry = QLineEdit()
        self.key_file_entry.setReadOnly(True)
        layout.addWidget(self.key_file_entry, 2, 1)
        browse_key_btn = QPushButton("Browse Key File")
        browse_key_btn.clicked.connect(self.browse_key_file)
        layout.addWidget(browse_key_btn, 2, 2)
        
        # Connect text change events for live preview updates
        self.uid_entry.textChanged.connect(self.update_command_preview)
        self.key_hex_entry.textChanged.connect(self.update_command_preview)
        self.key_file_entry.textChanged.connect(self.update_command_preview)
        
        return settings_group

    def auto_populate_found_files(self):
        """Populate encrypt/decrypt found files from input directories"""
        # Populate encrypt found files from input_encrypt
        encrypt_dir = os.path.join(os.getcwd(), 'input_encrypt')
        if os.path.exists(encrypt_dir):
            encrypt_files = [os.path.join(encrypt_dir, f) for f in os.listdir(encrypt_dir) 
                           if f.lower().endswith('.yaml')]
            self._encrypt_found_files = encrypt_files
            self.encrypt_found_listbox.clear()
            for f in encrypt_files:
                self.encrypt_found_listbox.addItem(os.path.basename(f))
        
        # Populate decrypt found files from input_decrypt
        decrypt_dir = os.path.join(os.getcwd(), 'input_decrypt')
        if os.path.exists(decrypt_dir):
            decrypt_files = [os.path.join(decrypt_dir, f) for f in os.listdir(decrypt_dir) 
                           if f.lower().endswith('.sav')]
            self._decrypt_found_files = decrypt_files
            self.decrypt_found_listbox.clear()
            for f in decrypt_files:
                self.decrypt_found_listbox.addItem(os.path.basename(f))

    def refresh_decrypt(self):
        """Clear decrypt lists and refresh"""
        self.decrypt_input_files.clear()
        self._decrypt_found_files.clear()
        self.decrypt_files_listbox.clear()
        self.decrypt_found_listbox.clear()
        self.auto_populate_found_files()
        self.update_command_preview()

    def refresh_encrypt(self):
        """Clear encrypt lists and refresh"""
        self.encrypt_input_files.clear()
        self._encrypt_found_files.clear()
        self.encrypt_files_listbox.clear()
        self.encrypt_found_listbox.clear()
        self.auto_populate_found_files()
        self.update_command_preview()

    def scan_decrypt_dirs(self):
        """Scan decrypt directory for .sav files"""
        self.decrypt_found_listbox.clear()
        decrypt_dir = os.path.join(os.getcwd(), 'input_decrypt')
        if os.path.exists(decrypt_dir):
            files = [os.path.join(decrypt_dir, f) for f in os.listdir(decrypt_dir) 
                    if f.lower().endswith('.sav')]
            files = [f for f in files if f not in self.decrypt_input_files]
            self._decrypt_found_files = files
            for f in files:
                self.decrypt_found_listbox.addItem(os.path.basename(f))

    def scan_encrypt_dirs(self):
        """Scan encrypt directory for .yaml files"""
        self.encrypt_found_listbox.clear()
        encrypt_dir = os.path.join(os.getcwd(), 'input_encrypt')
        if os.path.exists(encrypt_dir):
            files = [os.path.join(encrypt_dir, f) for f in os.listdir(encrypt_dir) 
                    if f.lower().endswith('.yaml')]
            files = [f for f in files if f not in self.encrypt_input_files]
            self._encrypt_found_files = files
            for f in files:
                self.encrypt_found_listbox.addItem(os.path.basename(f))

    def move_found_to_change(self, mode):
        """Move file from found list to change list"""
        if mode == 'decrypt':
            current_row = self.decrypt_found_listbox.currentRow()
            if current_row >= 0 and current_row < len(self._decrypt_found_files):
                fname = self._decrypt_found_files[current_row]
                if fname not in self.decrypt_input_files:
                    self.decrypt_input_files.append(fname)
                    self.decrypt_files_listbox.addItem(os.path.basename(fname))
                self.decrypt_found_listbox.takeItem(current_row)
                self._decrypt_found_files.pop(current_row)
        else:
            current_row = self.encrypt_found_listbox.currentRow()
            if current_row >= 0 and current_row < len(self._encrypt_found_files):
                fname = self._encrypt_found_files[current_row]
                if fname not in self.encrypt_input_files:
                    self.encrypt_input_files.append(fname)
                    self.encrypt_files_listbox.addItem(os.path.basename(fname))
                self.encrypt_found_listbox.takeItem(current_row)
                self._encrypt_found_files.pop(current_row)
        self.update_command_preview()

    def move_change_to_found(self, mode):
        """Move file from change list back to found list"""
        if mode == 'decrypt':
            current_row = self.decrypt_files_listbox.currentRow()
            if current_row >= 0 and current_row < len(self.decrypt_input_files):
                fname = self.decrypt_input_files[current_row]
                self._decrypt_found_files.append(fname)
                self.decrypt_found_listbox.addItem(os.path.basename(fname))
                self.decrypt_files_listbox.takeItem(current_row)
                self.decrypt_input_files.pop(current_row)
        else:
            current_row = self.encrypt_files_listbox.currentRow()
            if current_row >= 0 and current_row < len(self.encrypt_input_files):
                fname = self.encrypt_input_files[current_row]
                self._encrypt_found_files.append(fname)
                self.encrypt_found_listbox.addItem(os.path.basename(fname))
                self.encrypt_files_listbox.takeItem(current_row)
                self.encrypt_input_files.pop(current_row)
        self.update_command_preview()

    def save_uid(self):
        """Save Steam UID to file"""
        uid = self.uid_entry.text().strip()
        if uid:
            try:
                with open(UID_FILE, 'w') as f:
                    f.write(uid)
                QMessageBox.information(self, 'Saved', 'Steam UID saved!')
            except Exception as e:
                QMessageBox.critical(self, 'Error', f'Failed to save UID: {e}')
        else:
            QMessageBox.warning(self, 'Warning', 'Please enter a Steam UID.')

    def save_key_hex(self):
        """Save key hex to file"""
        key = self.key_hex_entry.text().strip()
        if key:
            try:
                with open('key.txt', 'w') as f:
                    f.write(key)
                QMessageBox.information(self, 'Saved', 'Key hex saved to key.txt!')
            except Exception as e:
                QMessageBox.critical(self, 'Error', f'Failed to save key: {e}')
        else:
            QMessageBox.warning(self, 'Warning', 'Please enter a key hex.')

    def load_uid(self):
        """Load Steam UID from file"""
        if os.path.exists(UID_FILE):
            try:
                with open(UID_FILE, 'r') as f:
                    uid = f.read().strip()
                    if hasattr(self, 'uid_entry'):
                        self.uid_entry.setText(uid)
                    else:
                        self._saved_uid = uid
            except Exception:
                pass

    def browse_key_file(self):
        """Browse for key file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, 'Select Key File', '', 'All Files (*.*)')
        if file_path:
            self.key_file_entry.setText(file_path)

    def decrypt_file(self):
        """Decrypt selected files"""
        output_dir = os.path.join(os.getcwd(), 'output_decrypt')
        self.ensure_dir(output_dir)
        
        if not self.decrypt_input_files:
            QMessageBox.warning(self, 'Warning', 'Please select input files.')
            return
        
        errors = []
        for f in self.decrypt_input_files:
            base = os.path.splitext(os.path.basename(f))[0]
            out_file = os.path.join(output_dir, base + '.yaml')
            cmd = [BL4_CRYPT_EXE, 'decrypt', '-i', f, '-o', out_file]
            
            uid = self.uid_entry.text().strip()
            if uid:
                cmd += ['-s', uid]
            
            key_hex_val = self.key_hex_entry.text().strip()
            key_file_val = self.key_file_entry.text().strip()
            if key_hex_val:
                cmd += ['-h', key_hex_val]
            elif key_file_val:
                cmd += ['-f', key_file_val]
            
            try:
                self.run_cmd(cmd)
            except Exception as e:
                errors.append(f"{os.path.basename(f)}: {e}")
        
        if len(self.decrypt_input_files) > 1:
            if errors:
                QMessageBox.critical(self, 'Error', 
                    'Some files failed to decrypt:\n' + '\n'.join(errors))
            else:
                QMessageBox.information(self, 'Success', 'All files decrypted successfully.')
        elif self.decrypt_input_files:
            if errors:
                QMessageBox.critical(self, 'Error', 
                    f'Failed to decrypt {os.path.basename(self.decrypt_input_files[0])}: {errors[0]}')
            else:
                QMessageBox.information(self, 'Success', 
                    f'Decryption complete for {os.path.basename(self.decrypt_input_files[0])}.')

    def encrypt_file(self):
        """Encrypt selected files"""
        output_dir = os.path.join(os.getcwd(), 'output_encrypt')
        self.ensure_dir(output_dir)
        
        if not self.encrypt_input_files:
            QMessageBox.warning(self, 'Warning', 'Please select input files.')
            return
        
        errors = []
        for f in self.encrypt_input_files:
            base = os.path.splitext(os.path.basename(f))[0]
            out_file = os.path.join(output_dir, base + '.sav')
            cmd = [BL4_CRYPT_EXE, 'encrypt', '-i', f, '-o', out_file]
            
            uid = self.uid_entry.text().strip()
            if uid:
                cmd += ['-s', uid]
            
            key_hex_val = self.key_hex_entry.text().strip()
            key_file_val = self.key_file_entry.text().strip()
            if key_hex_val:
                cmd += ['-h', key_hex_val]
            elif key_file_val:
                cmd += ['-f', key_file_val]
            
            try:
                self.run_cmd(cmd)
            except Exception as e:
                errors.append(f"{os.path.basename(f)}: {e}")
        
        if len(self.encrypt_input_files) > 1:
            if errors:
                QMessageBox.critical(self, 'Error', 
                    'Some files failed to encrypt:\n' + '\n'.join(errors))
            else:
                QMessageBox.information(self, 'Success', 'All files encrypted successfully.')
        elif self.encrypt_input_files:
            if errors:
                QMessageBox.critical(self, 'Error', 
                    f'Failed to encrypt {os.path.basename(self.encrypt_input_files[0])}: {errors[0]}')
            else:
                QMessageBox.information(self, 'Success', 
                    f'Encryption complete for {os.path.basename(self.encrypt_input_files[0])}.')

    def update_command_preview(self):
        """Update command preview displays"""
        # Encrypt command preview
        enc_cmd = [BL4_CRYPT_EXE, 'encrypt']
        for f in self.encrypt_input_files:
            enc_cmd += ['-i', f]
        enc_cmd += ['-d', os.path.join(os.getcwd(), 'output_encrypt')]
        
        uid = self.uid_entry.text().strip() if hasattr(self, 'uid_entry') else ''
        if uid:
            enc_cmd += ['-s', uid]
        
        key_hex = self.key_hex_entry.text().strip() if hasattr(self, 'key_hex_entry') else ''
        key_file = self.key_file_entry.text().strip() if hasattr(self, 'key_file_entry') else ''
        if key_hex:
            enc_cmd += ['-h', key_hex]
        elif key_file:
            enc_cmd += ['-f', key_file]
        
        enc_cmd_str = ' '.join(f'"{c}"' if ' ' in c else c for c in enc_cmd)
        if hasattr(self, 'encrypt_command_preview'):
            self.encrypt_command_preview.setText(enc_cmd_str)
        
        # Decrypt command preview
        dec_cmd = [BL4_CRYPT_EXE, 'decrypt']
        for f in self.decrypt_input_files:
            dec_cmd += ['-i', f]
        dec_cmd += ['-d', os.path.join(os.getcwd(), 'output_decrypt')]
        
        if uid:
            dec_cmd += ['-s', uid]
        if key_hex:
            dec_cmd += ['-h', key_hex]
        elif key_file:
            dec_cmd += ['-f', key_file]
        
        dec_cmd_str = ' '.join(f'"{c}"' if ' ' in c else c for c in dec_cmd)
        if hasattr(self, 'decrypt_command_preview'):
            self.decrypt_command_preview.setText(dec_cmd_str)

    def run_cmd(self, cmd):
        """Run command and handle errors"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result
        except subprocess.CalledProcessError as e:
            raise Exception(e.stderr.strip() or str(e))
        except FileNotFoundError:
            raise Exception(f"Command not found: {cmd[0]}. Make sure {BL4_CRYPT_EXE} is in your PATH or current directory.")
def main():
    app = QApplication(sys.argv)
    
    # Apply dark theme
    app.setStyleSheet(DARK_THEME)
    
    # Create main window
    window = BL4CryptApp()
    
    # Set up saved UID if it exists
    if hasattr(window, '_saved_uid'):
        window.uid_entry.setText(window._saved_uid)
        window.update_command_preview()
    
    window.show()
    
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
