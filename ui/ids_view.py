from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QCheckBox, QTextEdit, QFrame
)
from PyQt6.QtCore import Qt
from core.ai_ids_engine import AIIDSEngine

class IDSView(QWidget):
    """AI IDS monitoring dashboard with sub-vector toggles and live log telemetry."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ids_engine = AIIDSEngine()
        self.ids_engine.log_signal.connect(self._append_log)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Header with Master Toggle
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

        # Sub-vectors Card
        sub_card = QFrame()
        sub_card.setProperty("class", "card")
        sub_layout = QHBoxLayout(sub_card)

        self.cb_port = QCheckBox("Port Scan Detection")
        self.cb_port.setChecked(True)
        self.cb_port.toggled.connect(lambda v: setattr(self.ids_engine, 'detect_port_scan', v))

        self.cb_syn = QCheckBox("SYN Flood / DoS")
        self.cb_syn.setChecked(True)
        self.cb_syn.toggled.connect(lambda v: setattr(self.ids_engine, 'detect_syn_flood', v))

        self.cb_entropy = QCheckBox("Payload Entropy / Shellcode")
        self.cb_entropy.setChecked(True)
        self.cb_entropy.toggled.connect(lambda v: setattr(self.ids_engine, 'detect_payload_entropy', v))

        self.cb_ai = QCheckBox("AI ML Anomaly Classifier")
        self.cb_ai.setChecked(True)
        self.cb_ai.toggled.connect(lambda v: setattr(self.ids_engine, 'enable_ai_classifier', v))

        sub_layout.addWidget(self.cb_port)
        sub_layout.addWidget(self.cb_syn)
        sub_layout.addWidget(self.cb_entropy)
        sub_layout.addWidget(self.cb_ai)
        layout.addWidget(sub_card)

        # Log Terminal
        log_label = QLabel("Live Intrusion Telemetry:")
        log_label.setStyleSheet("color: #a0a0b0; font-weight: bold;")
        layout.addWidget(log_label)

        self.log_terminal = QTextEdit()
        self.log_terminal.setObjectName("LogTerminal")
        self.log_terminal.setReadOnly(True)
        layout.addWidget(self.log_terminal)

    def _toggle_master_ids(self, checked):
        if checked:
            self.master_btn.setText("Disable IDS Engine")
            self.master_btn.setProperty("class", "danger-btn")
            self.master_btn.setStyleSheet("background-color: #ff3366; color: white;")
            self.ids_engine.start()
        else:
            self.master_btn.setText("Enable IDS Engine")
            self.master_btn.setProperty("class", "action-btn")
            self.master_btn.setStyleSheet("")
            self.ids_engine.stop()
            self._append_log("[*] AI IDS Engine Disarmed.", False)

    def _append_log(self, text: str, is_suspicious: bool):
        color = "#ff3366" if is_suspicious else "#00f0c0"
        html = f'<span style="color: {color};">{text}</span>'
        self.log_terminal.append(html)
        self.log_terminal.verticalScrollBar().setValue(self.log_terminal.verticalScrollBar().maximum())