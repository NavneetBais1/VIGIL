import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QStackedWidget, QFrame
)
from PyQt6.QtCore import Qt

from core.auth_manager import AuthManager
from ui.styles import DARK_THEME_QSS
from ui.auth_dialog import StartupAuthDialog
from ui.settings_dialog import SettingsDialog
from ui.ids_view import IDSView
from ui.vault_view import VaultView

class VigilMainWindow(QMainWindow):
    def __init__(self, auth_manager: AuthManager):
        super().__init__()
        self.auth_manager = auth_manager
        self.setWindowTitle("Vigil — AI Security Suite")
        self.resize(1100, 720)
        self.setStyleSheet(DARK_THEME_QSS)
        self._init_ui()

    def _init_ui(self):
        main_widget = QWidget()
        main_widget.setObjectName("CentralCanvas")
        self.setCentralWidget(main_widget)
        
        root_layout = QVBoxLayout(main_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # Top Header Bar (Full OLED black with 1px white bottom rule)
        header = QFrame()
        header.setObjectName("HeaderFrame")
        header.setFixedHeight(62)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(24, 0, 24, 0)

        logo = QLabel("V I G I L")
        logo.setObjectName("LogoLabel")
        header_layout.addWidget(logo)

        header_layout.addStretch()

        # Settings Gear: padded so it doesn't touch or overlap OS window controls
        gear_btn = QPushButton("⚙")
        gear_btn.setObjectName("GearButton")
        gear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        gear_btn.clicked.connect(self._open_settings)
        header_layout.addWidget(gear_btn)

        root_layout.addWidget(header)

        # Main Body
        body = QWidget()
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        # Left Sidebar (Pitch black, bounded by right 1px white line)
        sidebar = QFrame()
        sidebar.setObjectName("SidebarFrame")
        sidebar.setFixedWidth(250)
        side_layout = QVBoxLayout(sidebar)
        side_layout.setContentsMargins(8, 20, 8, 20)
        side_layout.setSpacing(10)

        self.nav_buttons = []

        self.btn_ids = QPushButton("🛡️  AI Intrusion Detection")
        self.btn_ids.setProperty("class", "nav-btn")
        self.btn_ids.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_ids.clicked.connect(lambda: self._switch_tab(0))
        side_layout.addWidget(self.btn_ids)
        self.nav_buttons.append(self.btn_ids)

        self.btn_vault = QPushButton("🔐  Post-Quantum Vault")
        self.btn_vault.setProperty("class", "nav-btn")
        self.btn_vault.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_vault.clicked.connect(lambda: self._switch_tab(1))
        side_layout.addWidget(self.btn_vault)
        self.nav_buttons.append(self.btn_vault)

        side_layout.addStretch()
        body_layout.addWidget(sidebar)

        # Right Content View
        self.stack = QStackedWidget()
        self.view_ids = IDSView()
        self.view_vault = VaultView(self.auth_manager)

        self.stack.addWidget(self.view_ids)
        self.stack.addWidget(self.view_vault)

        body_layout.addWidget(self.stack)
        root_layout.addWidget(body)

        self._switch_tab(0)

    def _switch_tab(self, index: int):
        self.stack.setCurrentIndex(index)
        for i, btn in enumerate(self.nav_buttons):
            btn.setProperty("active", "true" if i == index else "false")
            btn.style().unpolish(btn)
            btn.style().polish(btn)

    def _open_settings(self):
        dlg = SettingsDialog(self.auth_manager, self)
        dlg.exec()

def main():
    app = QApplication(sys.argv)
    auth_mgr = AuthManager()

    auth_dialog = StartupAuthDialog(auth_mgr)
    if auth_dialog.exec() != StartupAuthDialog.DialogCode.Accepted:
        sys.exit(0)

    window = VigilMainWindow(auth_mgr)
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()