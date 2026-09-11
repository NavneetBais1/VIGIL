from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QPushButton, QMessageBox, QWidget
)
from PyQt6.QtCore import Qt, QPropertyAnimation, pyqtProperty, QEasingCurve, QPointF
from PyQt6.QtGui import QPainter, QPen, QColor, QPainterPath, QFont
from core.auth_manager import AuthManager


class AnimatedEyeToggle(QWidget):
    """Minimal vector eye toggle painted with anti-aliased lines."""
    def __init__(self, target_line_edit: QLineEdit, parent=None):
        super().__init__(parent)
        self.target = target_line_edit
        self.setFixedSize(30, 26)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        
        self._is_visible = False
        self._hover = False
        self._anim_progress = 0.0  # 0.0 = slashed/closed, 1.0 = open

        self.anim = QPropertyAnimation(self, b"anim_progress")
        self.anim.setDuration(220)
        self.anim.setEasingCurve(QEasingCurve.Type.InOutCubic)

    @pyqtProperty(float)
    def anim_progress(self):
        return self._anim_progress

    @anim_progress.setter
    def anim_progress(self, val):
        self._anim_progress = val
        self.update()

    def enterEvent(self, event):
        self._hover = True
        self.update()

    def leaveEvent(self, event):
        self._hover = False
        self.update()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._is_visible = not self._is_visible
            
            if self._is_visible:
                self.target.setEchoMode(QLineEdit.EchoMode.Normal)
                self.anim.stop()
                self.anim.setStartValue(self._anim_progress)
                self.anim.setEndValue(1.0)
                self.anim.start()
            else:
                self.target.setEchoMode(QLineEdit.EchoMode.Password)
                self.anim.stop()
                self.anim.setStartValue(self._anim_progress)
                self.anim.setEndValue(0.0)
                self.anim.start()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        line_color = QColor("#00f0c0") if self._hover else QColor("#5eead4")
        dim_color = QColor("#00f0c0" if self._hover else "#2dd4bf")

        pen = QPen(line_color, 1.7, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)
        p.setPen(pen)

        w = self.width()
        h = self.height()
        cx, cy = w / 2.0, h / 2.0

        t = self._anim_progress

        # 1. Upper Eyelid curve
        upper_height = 4.0 + (4.0 * t)
        upper_path = QPainterPath()
        upper_path.moveTo(cx - 9, cy)
        upper_path.quadTo(QPointF(cx, cy - upper_height), QPointF(cx + 9, cy))
        p.drawPath(upper_path)

        # 2. Lower Eyelid curve
        lower_height = 4.0 + (4.0 * t)
        lower_path = QPainterPath()
        lower_path.moveTo(cx - 9, cy)
        lower_path.quadTo(QPointF(cx, cy + lower_height), QPointF(cx + 9, cy))
        p.drawPath(lower_path)

        # 3. Center Iris / Pupil
        pupil_radius = 2.2 + (0.6 * t)
        p.setBrush(line_color)
        p.drawEllipse(QPointF(cx, cy), pupil_radius, pupil_radius)
        p.setBrush(Qt.BrushStyle.NoBrush)

        # 4. Radiating lashes when open
        if t > 0.3:
            lash_pen = QPen(dim_color, 1.2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
            lash_pen.setColor(QColor(0, 240, 192, int(220 * (t - 0.3) / 0.7)))
            p.setPen(lash_pen)
            
            p.drawLine(QPointF(cx - 6, cy - upper_height + 1), QPointF(cx - 9, cy - upper_height - 3))
            p.drawLine(QPointF(cx, cy - upper_height), QPointF(cx, cy - upper_height - 4))
            p.drawLine(QPointF(cx + 6, cy - upper_height + 1), QPointF(cx + 9, cy - upper_height - 3))

        # 5. Strike slash when closed
        if t < 0.85:
            slash_alpha = int(255 * (1.0 - (t / 0.85)))
            slash_pen = QPen(QColor(0, 240, 192, slash_alpha), 1.8, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
            p.setPen(slash_pen)
            p.drawLine(QPointF(cx - 8, cy - 7), QPointF(cx + 8, cy + 7))


class PasswordFieldWithEye(QLineEdit):
    """QLineEdit with built-in embedded animated vector eye toggle."""
    def __init__(self, placeholder: str, is_secret: bool = True, parent=None):
        super().__init__(parent)
        self.setPlaceholderText(placeholder)
        if is_secret:
            self.setEchoMode(QLineEdit.EchoMode.Password)

        self.setTextMargins(12, 0, 38, 0)
        self.setFixedHeight(40)

        self.eye = AnimatedEyeToggle(self, self)
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 8, 0)
        layout.addStretch()
        layout.addWidget(self.eye)


class StartupAuthDialog(QDialog):
    """Authentication screen with complete field pairs and Courier branding."""
    def __init__(self, auth_manager: AuthManager, parent=None):
        super().__init__(parent)
        self.auth_manager = auth_manager
        self.attempts_left = 3
        self.in_security_question_mode = False

        self.setWindowTitle("Vigil — Access Lock")
        self.setFixedWidth(520)
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.CustomizeWindowHint | Qt.WindowType.WindowTitleHint)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 32, 36, 32)
        layout.setSpacing(14)

        # Prominent Courier branding
        self.logo_label = QLabel("V I G I L")
        courier_font = QFont("OCR A Extended")
        courier_font.setBold(True)
        courier_font.setPointSize(26)
        courier_font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 10)
        self.logo_label.setFont(courier_font)
        self.logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.logo_label.setStyleSheet("color: #ffffff; background-color: transparent; margin-bottom: 6px;")
        layout.addWidget(self.logo_label)

        if not self.auth_manager.is_initialized():
            self.setFixedHeight(530)

            self.title_label = QLabel("Create Master Security Profile")
            self.title_label.setStyleSheet("color: #00f0c0; font-weight: bold; font-size: 15px; margin-bottom: 6px;")
            self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(self.title_label)

            # Master Password + Confirmation
            self.pw_input = PasswordFieldWithEye("Master Password")
            layout.addWidget(self.pw_input)

            self.pw_confirm = PasswordFieldWithEye("Confirm Master Password")
            layout.addWidget(self.pw_confirm)

            # Security Question
            self.ques_input = QLineEdit()
            self.ques_input.setPlaceholderText("Personal Security Question (e.g. Secret Pet Name)")
            self.ques_input.setFixedHeight(40)
            self.ques_input.setTextMargins(12, 0, 12, 0)
            layout.addWidget(self.ques_input)

            # Secret Answer + Confirmation
            self.ans_input = PasswordFieldWithEye("Secret Answer (ignores case and spaces)")
            layout.addWidget(self.ans_input)

            self.ans_confirm = PasswordFieldWithEye("Confirm Secret Answer")
            layout.addWidget(self.ans_confirm)

            self.action_btn = QPushButton("Initialize Suite")
            self.action_btn.setProperty("class", "action-btn")
            self.action_btn.setFixedHeight(42)
            self.action_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self.action_btn.clicked.connect(self._handle_initialization)
            layout.addWidget(self.action_btn)

        else:
            self.setFixedHeight(340)

            self.info_label = QLabel("Enter Master Password to Unlock:")
            self.info_label.setStyleSheet("color: #ffffff; font-size: 13px;")
            layout.addWidget(self.info_label)

            self.input_field = PasswordFieldWithEye("Master Password")
            layout.addWidget(self.input_field)

            self.status_label = QLabel(f"Attempts remaining: {self.attempts_left}")
            self.status_label.setStyleSheet("color: #a0a0b0; font-size: 12px;")
            layout.addWidget(self.status_label)

            self.submit_btn = QPushButton("Unlock Suite")
            self.submit_btn.setProperty("class", "action-btn")
            self.submit_btn.setFixedHeight(42)
            self.submit_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self.submit_btn.clicked.connect(self._handle_login)
            layout.addWidget(self.submit_btn)

    def _handle_initialization(self):
        pw = self.pw_input.text()
        pw_c = self.pw_confirm.text()
        q = self.ques_input.text().strip()
        ans = self.ans_input.text()
        ans_c = self.ans_confirm.text()

        # Validation Checks
        if not pw or not pw_c or not q or not ans or not ans_c:
            QMessageBox.warning(self, "Setup Incomplete", "Please complete all fields.")
            return

        if len(pw) < 4:
            QMessageBox.warning(self, "Password Too Short", "Password must be at least 4 characters long.")
            return

        if pw != pw_c:
            QMessageBox.warning(self, "Password Mismatch", "The master passwords entered do not match.")
            self.pw_confirm.clear()
            return

        norm_ans = AuthManager._normalize_answer(ans)
        norm_ans_c = AuthManager._normalize_answer(ans_c)
        if norm_ans != norm_ans_c:
            QMessageBox.warning(self, "Answer Mismatch", "The security answers entered do not match.")
            self.ans_confirm.clear()
            return

        self.auth_manager.set_credentials(pw, q, ans)
        QMessageBox.information(self, "Initialized", "Vigil Security Profile generated successfully.")
        self.accept()

    def _handle_login(self):
        entered_text = self.input_field.text()

        if not self.in_security_question_mode:
            if self.auth_manager.verify_password(entered_text):
                self.accept()
            else:
                self.attempts_left -= 1
                self.input_field.clear()

                if self.attempts_left > 0:
                    self.status_label.setText(f"Incorrect Password. Attempts remaining: {self.attempts_left}")
                    self.status_label.setStyleSheet("color: #ff3366;")
                else:
                    self.in_security_question_mode = True
                    self.attempts_left = 3
                    self.info_label.setText(f"Password failed. Question:\n{self.auth_manager.get_security_question()}")
                    self.info_label.setStyleSheet("color: #00f0c0; font-weight: bold;")
                    self.input_field.setPlaceholderText("Answer (case & space insensitive)")
                    self.input_field.setEchoMode(QLineEdit.EchoMode.Normal)
                    self.status_label.setText(f"Recovery attempts remaining: {self.attempts_left}")
                    self.submit_btn.setText("Verify Recovery Answer")
        else:
            if self.auth_manager.verify_security_answer(entered_text):
                QMessageBox.information(self, "Recovery Accepted", "Identity verified through security question.")
                self.accept()
            else:
                self.attempts_left -= 1
                self.input_field.clear()
                if self.attempts_left > 0:
                    self.status_label.setText(f"Incorrect Answer. Attempts remaining: {self.attempts_left}")
                else:
                    QMessageBox.critical(self, "Locked Out", "Maximum recovery attempts exceeded. Access Terminated.")
                    self.reject()