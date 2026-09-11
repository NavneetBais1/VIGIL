DARK_THEME_QSS = """
/* Global Canvas: Pure OLED Pitch Black (#000000) */
QMainWindow, QDialog, QWidget {
    background-color: #000000;
    color: #ffffff;
    font-family: Arial, "Segoe UI", sans-serif;
    font-size: 13px;
    border: none;
}

/* Header Container */
#HeaderFrame {
    background-color: #000000;
    border: none;
    border-bottom: 1px solid #ffffff;
}

/* Logo */
#LogoLabel {
    font-family: "OCR A Extended", "Courier New", monospace;
    font-size: 22px;
    font-weight: bold;
    color: #ffffff;
    letter-spacing: 5px;
    background-color: #000000;
    border: none;
    padding: 0px 8px;
}

/* Settings Gear */
#GearButton {
    background-color: #000000;
    color: #00f0c0;
    font-size: 20px;
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 4px 10px;
}
#GearButton:hover {
    border: 1px solid #00f0c0;
    background-color: #000000;
}

/* Sidebar */
#SidebarFrame {
    background-color: #000000;
    border: none;
    border-right: 1px solid #ffffff;
}

/* Nav Buttons */
QPushButton.nav-btn {
    background-color: #000000;
    color: #ffffff;
    text-align: left;
    padding: 12px 18px;
    font-size: 13px;
    font-weight: 500;
    border: 1px solid transparent;
    border-radius: 8px;
    margin: 4px 10px;
}

QPushButton.nav-btn:hover {
    border: 1px solid #00f0c0;
    color: #00f0c0;
    background-color: #000000;
}

QPushButton.nav-btn[active="true"] {
    border: 1px solid #00f0c0;
    color: #00f0c0;
    background-color: #000000;
    font-weight: bold;
}

/* Structural Cards */
QFrame.card {
    background-color: #000000;
    border: 1px solid #ffffff;
    border-radius: 8px;
    padding: 16px;
}

/* Checkboxes */
QCheckBox {
    background-color: #000000;
    color: #ffffff;
    spacing: 10px;
}

QCheckBox::indicator {
    width: 18px;
    height: 18px;
    background-color: #000000;
    border: 1px solid #ffffff;
    border-radius: 3px;
}

QCheckBox::indicator:hover {
    border: 1px solid #00f0c0;
}

QCheckBox::indicator:checked {
    background-color: #00f0c0;
    border: 1px solid #00f0c0;
}

/* Inputs (Generous vertical clearance so text never gets cropped) */
QLineEdit {
    background-color: #000000;
    color: #ffffff;
    border: 1px solid #ffffff;
    border-radius: 6px;
    padding: 6px 12px;
    min-height: 24px;
    font-size: 13px;
}
QLineEdit:focus {
    border: 1px solid #00f0c0;
}

/* Action Buttons */
QPushButton.action-btn {
    background-color: #000000;
    color: #00f0c0;
    font-weight: bold;
    font-size: 13px;
    padding: 6px 16px;
    min-height: 24px;
    border-radius: 6px;
    border: 1px solid #00f0c0;
}
QPushButton.action-btn:hover {
    background-color: #00f0c0;
    color: #000000;
}

/* Danger / Reset Buttons */
QPushButton.danger-btn {
    background-color: #000000;
    color: #ff3366;
    font-weight: bold;
    font-size: 13px;
    padding: 6px 16px;
    min-height: 24px;
    border-radius: 6px;
    border: 1px solid #ff3366;
}
QPushButton.danger-btn:hover {
    background-color: #ff3366;
    color: #000000;
}

/* Style Dialogs & MessageBoxes (Includes hover states on Yes/No/Cancel) */
QMessageBox {
    background-color: #000000;
    border: 1px solid #ffffff;
}

QMessageBox QLabel {
    color: #ffffff;
    font-size: 13px;
    background-color: transparent;
}

QMessageBox QPushButton {
    background-color: #000000;
    color: #ffffff;
    border: 1px solid #ffffff;
    border-radius: 5px;
    padding: 6px 20px;
    min-width: 60px;
    font-size: 12px;
    font-weight: bold;
}

QMessageBox QPushButton:hover {
    background-color: #00f0c0;
    color: #000000;
    border: 1px solid #00f0c0;
}

/* Log Terminals */
QTextEdit#LogTerminal {
    background-color: #000000;
    color: #00f0c0;
    font-family: "Consolas", monospace;
    font-size: 12px;
    border: 1px solid #ffffff;
    border-radius: 6px;
    padding: 8px;
}

/* Scrollbars */
QScrollBar:vertical {
    background: #000000;
    width: 8px;
}
QScrollBar::handle:vertical {
    background: #ffffff;
    border-radius: 4px;
}
QScrollBar::handle:vertical:hover {
    background: #00f0c0;
}
"""