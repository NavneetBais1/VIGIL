import hashlib
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QPushButton, QMessageBox, QFrame, QApplication
)
from PyQt6.QtCore import Qt
from core.auth_manager import AuthManager


class MasterResetAuthModal(QDialog):
    """Custom OLED security modal requiring master password to authorize a factory reset."""
    def __init__(self, auth_manager: AuthManager, parent=None):
        super().__init__(parent)
        self.auth_manager = auth_manager
        self.confirmed = False
        
        self.setWindowTitle("Authorize System Wipe")
        self.setFixedSize(460, 260)
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.CustomizeWindowHint | Qt.WindowType.WindowTitleHint)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        warning_title = QLabel("⚠️ CRITICAL CONFIRMATION")
        warning_title.setStyleSheet("color: #ff3366; font-size: 15px; font-weight: bold;")
        layout.addWidget(warning_title)

        msg = QLabel("Enter your Master Password to wipe all keys, configuration, and security credentials permanently.")
        msg.setWordWrap(True)
        msg.setStyleSheet("color: #ffffff; font-size: 13px; line-height: 1.4;")
        layout.addWidget(msg)

        self.pw_input = QLineEdit()
        self.pw_input.setPlaceholderText("Confirm Master Password")
        self.pw_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.pw_input)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setProperty("class", "action-btn")
        self.cancel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(self.cancel_btn)

        self.wipe_btn = QPushButton("Confirm Wipe")
        self.wipe_btn.setProperty("class", "danger-btn")
        self.wipe_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.wipe_btn.clicked.connect(self._verify_and_execute)
        btn_row.addWidget(self.wipe_btn)

        layout.addLayout(btn_row)

    def _verify_and_execute(self):
        entered_pw = self.pw_input.text()
        if not self.auth_manager.verify_password(entered_pw):
            QMessageBox.critical(self, "Access Denied", "Incorrect Master Password. Wipe aborted.")
            self.pw_input.clear()
            return
        
        self.confirmed = True
        self.accept()


class SettingsDialog(QDialog):
    """Settings interface with adjusted sizing and password verification for resets."""
    def __init__(self, auth_manager: AuthManager, parent=None):
        super().__init__(parent)
        self.auth_manager = auth_manager
        self.setWindowTitle("Vigil — Settings & Credentials")
        self.setFixedSize(540, 620)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(18)

        title = QLabel("System Settings & Credentials")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #00f0c0;")
        layout.addWidget(title)

        # 1. Update Master Password
        pw_card = QFrame()
        pw_card.setProperty("class", "card")
        pw_layout = QVBoxLayout(pw_card)
        pw_layout.setSpacing(10)

        pw_label = QLabel("Update Master Password:")
        pw_label.setStyleSheet("color: #ffffff; font-weight: bold; font-size: 13px;")
        pw_layout.addWidget(pw_label)

        self.curr_pw = QLineEdit()
        self.curr_pw.setPlaceholderText("Current Password")
        self.curr_pw.setEchoMode(QLineEdit.EchoMode.Password)
        pw_layout.addWidget(self.curr_pw)

        self.new_pw = QLineEdit()
        self.new_pw.setPlaceholderText("New Master Password")
        self.new_pw.setEchoMode(QLineEdit.EchoMode.Password)
        pw_layout.addWidget(self.new_pw)

        self.save_pw_btn = QPushButton("Update Password")
        self.save_pw_btn.setProperty("class", "action-btn")
        self.save_pw_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.save_pw_btn.clicked.connect(self._handle_password_change)
        pw_layout.addWidget(self.save_pw_btn)
        layout.addWidget(pw_card)

        # 2. Update Security Recovery Question
        rec_card = QFrame()
        rec_card.setProperty("class", "card")
        rec_layout = QVBoxLayout(rec_card)
        rec_layout.setSpacing(10)

        rec_label = QLabel("Update Security Question / Answer:")
        rec_label.setStyleSheet("color: #ffffff; font-weight: bold; font-size: 13px;")
        rec_layout.addWidget(rec_label)

        self.new_q = QLineEdit()
        self.new_q.setPlaceholderText("New Security Question")
        rec_layout.addWidget(self.new_q)

        self.new_a = QLineEdit()
        self.new_a.setPlaceholderText("New Secret Answer (ignores spaces & case)")
        rec_layout.addWidget(self.new_a)

        self.save_rec_btn = QPushButton("Save Recovery Question")
        self.save_rec_btn.setProperty("class", "action-btn")
        self.save_rec_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.save_rec_btn.clicked.connect(self._handle_recovery_change)
        rec_layout.addWidget(self.save_rec_btn)
        layout.addWidget(rec_card)

        # 3. Master Reset
        reset_card = QFrame()
        reset_card.setProperty("class", "card")
        reset_layout = QVBoxLayout(reset_card)
        reset_layout.setSpacing(10)

        reset_label = QLabel("Factory Reset Suite:")
        reset_label.setStyleSheet("color: #ff3366; font-weight: bold; font-size: 13px;")
        reset_layout.addWidget(reset_label)

        self.reset_btn = QPushButton("⚠️ Master Reset & Wipe Suite")
        self.reset_btn.setProperty("class", "danger-btn")
        self.reset_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.reset_btn.clicked.connect(self._handle_master_reset)
        reset_layout.addWidget(self.reset_btn)
        layout.addWidget(reset_card)

    def _handle_password_change(self):
        c_pw = self.curr_pw.text()
        n_pw = self.new_pw.text().strip()

        if not self.auth_manager.verify_password(c_pw):
            QMessageBox.warning(self, "Verification Failed", "Current password does not match.")
            return
        if len(n_pw) < 4:
            QMessageBox.warning(self, "Invalid Length", "New password must be at least 4 characters.")
            return

        self.auth_manager.update_password_only(n_pw)
        QMessageBox.information(self, "Success", "Master password has been updated.")
        self.curr_pw.clear()
        self.new_pw.clear()

    def _handle_recovery_change(self):
        q = self.new_q.text().strip()
        a = self.new_a.text().strip()
        if not q or not a:
            QMessageBox.warning(self, "Input Missing", "Both question and answer are required.")
            return

        self.auth_manager.config["security_question"] = q
        salt = self.auth_manager.config.get("salt", "")
        norm_ans = self.auth_manager._normalize_answer(a)
        self.auth_manager.config["security_answer_hash"] = hashlib.sha256((norm_ans + salt).encode()).hexdigest()
        self.auth_manager.save_config()
        QMessageBox.information(self, "Success", "Recovery credentials updated successfully.")
        self.new_q.clear()
        self.new_a.clear()

    def _handle_master_reset(self):
        modal = MasterResetAuthModal(self.auth_manager, self)
        if modal.exec() == QDialog.DialogCode.Accepted and modal.confirmed:
            self.auth_manager.reset_all_data()
            QMessageBox.information(
                self, 
                "System Wiped", 
                "All settings, passwords, and encryption configs have been deleted.\n\nThe application will now close."
            )
            QApplication.quit()