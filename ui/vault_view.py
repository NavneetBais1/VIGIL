import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFileDialog, QLineEdit, QMessageBox, QFrame
)
from core.pq_crypto import PostQuantumFileVault
from core.auth_manager import AuthManager

class VaultView(QWidget):
    """
    Post-Quantum File Encrypter and Vault.
    Guarantees that only explicitly user-selected files via '+' are modified.
    """
    def __init__(self, auth_manager: AuthManager, parent=None):
        super().__init__(parent)
        self.auth_manager = auth_manager
        self.selected_file_path = None
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        title = QLabel("Post-Quantum File Encrypter & Vault")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #ffffff;")
        layout.addWidget(title)

        # File Selector Card
        card = QFrame()
        card.setProperty("class", "card")
        card_layout = QVBoxLayout(card)

        select_btn_layout = QHBoxLayout()
        self.select_btn = QPushButton("➕  Select Target File (.txt, .csv, .vigil)")
        self.select_btn.setProperty("class", "action-btn")
        self.select_btn.clicked.connect(self._choose_file)
        select_btn_layout.addWidget(self.select_btn)
        select_btn_layout.addStretch()
        card_layout.addLayout(select_btn_layout)

        self.file_info_label = QLabel("No file selected. Only files you select will be processed.")
        self.file_info_label.setStyleSheet("color: #a0a0b0; font-size: 13px; margin-top: 8px;")
        card_layout.addWidget(self.file_info_label)

        layout.addWidget(card)

        # Operations Card
        ops_card = QFrame()
        ops_card.setProperty("class", "card")
        ops_layout = QVBoxLayout(ops_card)

        self.pw_input = QLineEdit()
        self.pw_input.setPlaceholderText("Enter Master / Encryption Password for File")
        self.pw_input.setEchoMode(QLineEdit.EchoMode.Password)
        ops_layout.addWidget(self.pw_input)

        btn_row = QHBoxLayout()
        self.encrypt_btn = QPushButton("🔒  Encrypt File (Post-Quantum Hybrid)")
        self.encrypt_btn.setProperty("class", "action-btn")
        self.encrypt_btn.clicked.connect(self._encrypt_action)
        btn_row.addWidget(self.encrypt_btn)

        self.decrypt_btn = QPushButton("🔓  Decrypt & Open in Default App")
        self.decrypt_btn.setProperty("class", "action-btn")
        self.decrypt_btn.clicked.connect(self._decrypt_action)
        btn_row.addWidget(self.decrypt_btn)

        ops_layout.addLayout(btn_row)
        layout.addWidget(ops_card)
        layout.addStretch()

    def _choose_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File for Post-Quantum Encryption/Decryption", "", "Compatible Files (*.txt *.csv *.vigil)"
        )
        if file_path:
            self.selected_file_path = file_path
            is_enc = PostQuantumFileVault.is_file_encrypted(file_path)
            status = "🔒 Encrypted .vigil format" if is_enc else "📄 Plaintext format"
            self.file_info_label.setText(f"Selected: {os.path.basename(file_path)} [{status}]\nPath: {file_path}")
            self.file_info_label.setStyleSheet("color: #00f0c0; font-size: 13px;")

    def _encrypt_action(self):
        if not self.selected_file_path:
            QMessageBox.warning(self, "File Missing", "Please select a file using the '+' button first.")
            return

        pw = self.pw_input.text()
        if not pw:
            QMessageBox.warning(self, "Password Required", "Provide a password to seal the file.")
            return

        try:
            out_file = PostQuantumFileVault.encrypt_file(self.selected_file_path, pw)
            QMessageBox.information(self, "Encrypted", f"File encrypted under Post-Quantum Hybrid Envelope:\n{out_file}")
            self.pw_input.clear()
            self._choose_file_manual(out_file)
        except Exception as e:
            QMessageBox.critical(self, "Encryption Error", str(e))

    def _decrypt_action(self):
        if not self.selected_file_path:
            QMessageBox.warning(self, "File Missing", "Please select a file using the '+' button first.")
            return

        pw = self.pw_input.text()
        if not pw:
            QMessageBox.warning(self, "Password Required", "Provide password to unseal and launch the file.")
            return

        try:
            temp_path = PostQuantumFileVault.decrypt_and_open_file(self.selected_file_path, pw)
            QMessageBox.information(
                self, "Decrypted & Launched",
                f"File successfully verified and opened with default app.\nEphemeral path: {temp_path}"
            )
            self.pw_input.clear()
        except Exception as e:
            QMessageBox.critical(self, "Decryption Failed", f"Failed to decrypt: {e}\n(Check password or integrity)")

    def _choose_file_manual(self, file_path):
        self.selected_file_path = file_path
        is_enc = PostQuantumFileVault.is_file_encrypted(file_path)
        status = "🔒 Encrypted .vigil format" if is_enc else "📄 Plaintext format"
        self.file_info_label.setText(f"Selected: {os.path.basename(file_path)} [{status}]\nPath: {file_path}")