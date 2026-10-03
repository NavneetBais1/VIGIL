from PyQt6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QMessageBox,
    QFrame,
    QApplication,
)
from PyQt6.QtCore import Qt
from core.auth_manager import AuthManager


class MasterResetAuthModal(QDialog):
    """Require the current master password before a factory reset."""

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

        msg = QLabel("Enter your Master Password to permanently remove Vigil's local authentication configuration.")
        msg.setWordWrap(True)
        layout.addWidget(msg)

        self.pw_input = QLineEdit()
        self.pw_input.setPlaceholderText("Confirm Master Password")
        self.pw_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.pw_input)

        row = QHBoxLayout()
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setProperty("class", "action-btn")
        self.cancel_btn.clicked.connect(self.reject)
        row.addWidget(self.cancel_btn)

        self.wipe_btn = QPushButton("Confirm Wipe")
        self.wipe_btn.setProperty("class", "danger-btn")
        self.wipe_btn.clicked.connect(self._verify_and_execute)
        row.addWidget(self.wipe_btn)
        layout.addLayout(row)

    def _verify_and_execute(self):
        if not self.auth_manager.verify_password(self.pw_input.text()):
            QMessageBox.critical(self, "Access Denied", "Incorrect Master Password. Wipe aborted.")
            self.pw_input.clear()
            return
        self.confirmed = True
        self.accept()


class SettingsDialog(QDialog):
    """Settings for changing authentication credentials and resetting local state."""

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

        pw_card = QFrame()
        pw_card.setProperty("class", "card")
        pw_layout = QVBoxLayout(pw_card)
        pw_layout.addWidget(QLabel("Update Master Password:"))

        self.curr_pw = QLineEdit()
        self.curr_pw.setPlaceholderText("Current Password")
        self.curr_pw.setEchoMode(QLineEdit.EchoMode.Password)
        pw_layout.addWidget(self.curr_pw)

        self.new_pw = QLineEdit()
        self.new_pw.setPlaceholderText("New Master Password (12+ characters)")
        self.new_pw.setEchoMode(QLineEdit.EchoMode.Password)
        pw_layout.addWidget(self.new_pw)

        self.confirm_new_pw = QLineEdit()
        self.confirm_new_pw.setPlaceholderText("Confirm New Master Password")
        self.confirm_new_pw.setEchoMode(QLineEdit.EchoMode.Password)
        pw_layout.addWidget(self.confirm_new_pw)

        self.save_pw_btn = QPushButton("Update Password")
        self.save_pw_btn.setProperty("class", "action-btn")
        self.save_pw_btn.clicked.connect(self._handle_password_change)
        pw_layout.addWidget(self.save_pw_btn)
        layout.addWidget(pw_card)

        rec_card = QFrame()
        rec_card.setProperty("class", "card")
        rec_layout = QVBoxLayout(rec_card)
        rec_layout.addWidget(QLabel("Update Recovery Question / Answer:"))

        self.new_q = QLineEdit()
        self.new_q.setPlaceholderText("New Security Question")
        rec_layout.addWidget(self.new_q)

        self.new_a = QLineEdit()
        self.new_a.setPlaceholderText("New Secret Answer")
        self.new_a.setEchoMode(QLineEdit.EchoMode.Password)
        rec_layout.addWidget(self.new_a)

        self.save_rec_btn = QPushButton("Save Recovery Question")
        self.save_rec_btn.setProperty("class", "action-btn")
        self.save_rec_btn.clicked.connect(self._handle_recovery_change)
        rec_layout.addWidget(self.save_rec_btn)
        layout.addWidget(rec_card)

        reset_card = QFrame()
        reset_card.setProperty("class", "card")
        reset_layout = QVBoxLayout(reset_card)
        reset_layout.addWidget(QLabel("Factory Reset Suite:"))
        self.reset_btn = QPushButton("⚠️ Master Reset & Wipe Suite")
        self.reset_btn.setProperty("class", "danger-btn")
        self.reset_btn.clicked.connect(self._handle_master_reset)
        reset_layout.addWidget(self.reset_btn)
        layout.addWidget(reset_card)

    def _handle_password_change(self):
        current = self.curr_pw.text()
        new = self.new_pw.text()
        confirm = self.confirm_new_pw.text()

        if not self.auth_manager.verify_password(current):
            QMessageBox.warning(self, "Verification Failed", "Current password does not match.")
            return
        if len(new) < 12:
            QMessageBox.warning(self, "Invalid Length", "New password must be at least 12 characters.")
            return
        if new != confirm:
            QMessageBox.warning(self, "Mismatch", "New passwords do not match.")
            return

        try:
            self.auth_manager.update_password_only(new)
        except (ValueError, RuntimeError) as exc:
            QMessageBox.critical(self, "Update Failed", str(exc))
            return

        QMessageBox.information(self, "Success", "Master password has been updated.")
        self.curr_pw.clear()
        self.new_pw.clear()
        self.confirm_new_pw.clear()

    def _handle_recovery_change(self):
        question = self.new_q.text().strip()
        answer = self.new_a.text()
        if not question or not answer:
            QMessageBox.warning(self, "Input Missing", "Both question and answer are required.")
            return

        try:
            self.auth_manager.update_security_credentials(question, answer)
        except (ValueError, RuntimeError) as exc:
            QMessageBox.critical(self, "Update Failed", str(exc))
            return

        QMessageBox.information(self, "Success", "Recovery credentials updated successfully.")
        self.new_q.clear()
        self.new_a.clear()

    def _handle_master_reset(self):
        modal = MasterResetAuthModal(self.auth_manager, self)
        if modal.exec() == QDialog.DialogCode.Accepted and modal.confirmed:
            try:
                self.auth_manager.reset_all_data()
            except OSError as exc:
                QMessageBox.critical(self, "Reset Failed", f"Could not remove local configuration: {exc}")
                return
            QMessageBox.information(self, "System Wiped", "Local authentication configuration has been removed. Vigil will close.")
            QApplication.quit()
