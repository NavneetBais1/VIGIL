from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QCheckBox,
    QTextEdit,
    QFrame,
    QSystemTrayIcon,
)
from PyQt6.QtCore import Qt, QTimer, QPoint
from PyQt6.QtGui import QIcon
from core.ai_ids_engine import AIIDSEngine


class IDSNotification(QFrame):
    """Small transient bottom-right in-app threat notification."""

    def __init__(self, parent, event, on_block, on_dismiss):
        super().__init__(parent)
        self.event = event
        self.on_block = on_block
        self.on_dismiss = on_dismiss

        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.Tool
            | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.setStyleSheet(
            """
            QFrame {
                background: #111318;
                border: 1px solid #ff3366;
                border-radius: 10px;
            }
            QLabel { color: #ffffff; }
            QPushButton {
                border: 0;
                border-radius: 5px;
                padding: 7px 12px;
                color: white;
            }
            QPushButton#blockButton { background: #ff3366; }
            QPushButton#closeButton { background: #30333b; }
            """
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(7)

        title = QLabel("🛡️  Vigil detected suspicious activity")
        title.setStyleSheet("font-weight: bold; color: #ff6688;")
        layout.addWidget(title)

        summary = QLabel(event.get("summary", "Suspicious network activity was detected."))
        summary.setWordWrap(True)
        layout.addWidget(summary)

        source = event.get("source_ip", "unknown")
        source_label = QLabel(f"Source: {source}")
        source_label.setStyleSheet("color: #a0a0b0;")
        layout.addWidget(source_label)

        buttons = QHBoxLayout()
        buttons.addStretch()

        block_button = QPushButton("Block source")
        block_button.setObjectName("blockButton")
        block_button.clicked.connect(self._block)
        buttons.addWidget(block_button)

        close_button = QPushButton("Dismiss")
        close_button.setObjectName("closeButton")
        close_button.clicked.connect(self._dismiss)
        buttons.addWidget(close_button)

        layout.addLayout(buttons)

        self.setFixedWidth(390)
        self.adjustSize()

        # Auto-dismiss after 15 seconds, while keeping the IDS log permanent.
        QTimer.singleShot(15000, self._dismiss)

    def _block(self):
        self.on_block(self.event)
        self._dismiss()

    def _dismiss(self):
        self.on_dismiss(self)


class IDSView(QWidget):
    """AI IDS monitoring dashboard with unchanged permanent layout."""

    def __init__(self, parent=None):
        super().__init__(parent)

        self.ids_engine = AIIDSEngine()
        self.ids_engine.log_signal.connect(self._append_log)
        self.ids_engine.intrusion_signal.connect(self._show_intrusion)

        self._notification = None
        self._tray = None

        self._init_ui()
        self._init_notifications()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Existing header — unchanged.
        header_layout = QHBoxLayout()
        title = QLabel("AI Intrusion Detection System")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #ffffff;")
        header_layout.addWidget(title)
        header_layout.addStretch()

        self.master_btn = QPushButton("Enable IDS Engine")
        self.master_btn.setProperty("class", "action-btn")
        self.master_btn.setCheckable(True)
        self.master_btn.clicked.connect(self._toggle_master_ids)
        header_layout.addWidget(self.master_btn)
        layout.addLayout(header_layout)

        # Existing feature switches — unchanged.
        sub_card = QFrame()
        sub_card.setProperty("class", "card")
        sub_layout = QHBoxLayout(sub_card)

        self.cb_port = QCheckBox("Port Scan Detection")
        self.cb_port.setChecked(True)
        self.cb_port.toggled.connect(
            lambda v: setattr(self.ids_engine, "detect_port_scan", v)
        )

        self.cb_syn = QCheckBox("SYN Flood / DoS")
        self.cb_syn.setChecked(True)
        self.cb_syn.toggled.connect(
            lambda v: setattr(self.ids_engine, "detect_syn_flood", v)
        )

        self.cb_entropy = QCheckBox("Payload Entropy / Shellcode")
        self.cb_entropy.setChecked(True)
        self.cb_entropy.toggled.connect(
            lambda v: setattr(self.ids_engine, "detect_payload_entropy", v)
        )

        self.cb_ai = QCheckBox("AI ML Anomaly Classifier")
        self.cb_ai.setChecked(True)
        self.cb_ai.toggled.connect(
            lambda v: setattr(self.ids_engine, "enable_ai_classifier", v)
        )

        sub_layout.addWidget(self.cb_port)
        sub_layout.addWidget(self.cb_syn)
        sub_layout.addWidget(self.cb_entropy)
        sub_layout.addWidget(self.cb_ai)
        layout.addWidget(sub_card)

        # Existing log area — unchanged.
        log_label = QLabel("Live Intrusion Telemetry:")
        log_label.setStyleSheet("color: #a0a0b0; font-weight: bold;")
        layout.addWidget(log_label)

        self.log_terminal = QTextEdit()
        self.log_terminal.setObjectName("LogTerminal")
        self.log_terminal.setReadOnly(True)
        layout.addWidget(self.log_terminal)

    def _init_notifications(self):
        # Windows notification center / bottom-right toast.
        if QSystemTrayIcon.isSystemTrayAvailable():
            self._tray = QSystemTrayIcon(QIcon(), self)
            self._tray.setToolTip("Vigil — AI Security Suite")
            self._tray.show()

    def _toggle_master_ids(self, checked):
        if checked:
            self.master_btn.setText("Disable IDS Engine")
            self.master_btn.setProperty("class", "danger-btn")
            self.master_btn.setStyleSheet("background-color: #ff3366; color: white;")

            # QThread objects cannot be started twice after finishing.
            # Recreate the engine if the user disabled it and enables it again.
            if self.ids_engine.isFinished():
                self.ids_engine = AIIDSEngine()
                self.ids_engine.log_signal.connect(self._append_log)
                self.ids_engine.intrusion_signal.connect(self._show_intrusion)

            self.ids_engine.start()
        else:
            self.master_btn.setText("Enable IDS Engine")
            self.master_btn.setProperty("class", "action-btn")
            self.master_btn.setStyleSheet("")
            self.ids_engine.stop()
            self._append_log("IDS has been turned off. Network monitoring is paused.", False)

    def _show_intrusion(self, event):
        """Show both the Windows toast and a temporary in-app action card."""
        summary = event.get("summary", "Suspicious network activity was detected.")
        source = event.get("source_ip", "unknown")
        details = event.get("details", "")

        if self._tray is not None:
            self._tray.showMessage(
                "Vigil — Intrusion detected",
                f"{summary}\nSource: {source}",
                QSystemTrayIcon.MessageIcon.Warning,
                8000,
            )

        if self._notification is not None:
            self._notification.close()
            self._notification.deleteLater()

        self._notification = IDSNotification(
            self,
            event,
            self._block_event,
            self._clear_notification,
        )
        self._position_notification()
        self._notification.show()
        self._notification.raise_()

        # Keep detailed information in the log, not in the toast.
        # The engine has already written the human-readable alert there.
        _ = details

    def _position_notification(self):
        if self._notification is None:
            return

        # Bottom-right of the visible IDS/main window, with a small margin.
        host = self.window()
        self._notification.adjustSize()
        x = host.x() + host.width() - self._notification.width() - 22
        y = host.y() + host.height() - self._notification.height() - 22
        self._notification.move(x, y)

    def _clear_notification(self, notification):
        if notification is self._notification:
            self._notification = None
        notification.close()
        notification.deleteLater()

    def _block_event(self, event):
        remote_ip = event.get("source_ip")
        success, message = self.ids_engine.block_remote_ip(remote_ip)

        if success:
            self._append_log(f"Protection action — {message}", False)
        else:
            self._append_log(f"Protection action failed — {message}", True)

    def _append_log(self, text: str, is_suspicious: bool):
        color = "#ff3366" if is_suspicious else "#00f0c0"
        html = f'<span style="color: {color};">{text}</span>'
        self.log_terminal.append(html)
        self.log_terminal.verticalScrollBar().setValue(
            self.log_terminal.verticalScrollBar().maximum()
        )

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._position_notification()

    def closeEvent(self, event):
        if self._notification is not None:
            self._notification.close()
        if self._tray is not None:
            self._tray.hide()
        self.ids_engine.stop()
        super().closeEvent(event)
