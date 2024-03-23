from PySide6.QtWidgets import QWidget, QFrame, QLabel, QTextEdit, QPushButton, QVBoxLayout, QHBoxLayout
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

from hashlib import sha256
from base64 import b64decode
import rsa

from api_request import request

header_font = QFont('Roboto', 18, QFont.Weight.Bold)
general_font = QFont('Roboto', 16)

class MainWindow(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self.send_message_frame = QFrame()
        self.send_message_frame.setFrameShape(QFrame.Box)

        self.send_message_label = QLabel("Отправить сообщение", )
        self.send_message_label.setFont(header_font)

        self.message_box = QTextEdit()
        self.message_box.setFont(general_font)

        self.send_correct_message_btn = QPushButton("Корректное")
        self.send_correct_message_btn.setFont(general_font)
        self.send_correct_message_btn.clicked.connect(self.on_send_correct_message_btn_clicked)

        self.send_incorrect_message_btn = QPushButton("Некорректное")
        self.send_incorrect_message_btn.setFont(general_font)
        self.send_incorrect_message_btn.clicked.connect(self.on_send_incorrect_message_btn_clicked)

        self.send_message_buttons_layout = QHBoxLayout()
        self.send_message_buttons_layout.addStretch(0)
        self.send_message_buttons_layout.addWidget(self.send_correct_message_btn, 0, Qt.AlignmentFlag.AlignCenter)
        self.send_message_buttons_layout.addWidget(self.send_incorrect_message_btn, 0, Qt.AlignmentFlag.AlignCenter)
        self.send_message_buttons_layout.addStretch(0)

        self.send_message_layout = QVBoxLayout(self.send_message_frame)
        self.send_message_layout.addWidget(self.send_message_label, 0, Qt.AlignmentFlag.AlignCenter)
        self.send_message_layout.addLayout(self.send_message_buttons_layout)
        self.send_message_layout.addWidget(self.message_box)

        self.receive_message_frame = QFrame()
        self.receive_message_frame.setFrameShape(QFrame.Box)

        self.receive_message_label = QLabel("Получить сообщение", )
        self.receive_message_label.setFont(header_font)

        self.receive_correct_message_btn = QPushButton("Корректное")
        self.receive_correct_message_btn.setFont(general_font)
        self.receive_correct_message_btn.clicked.connect(self.on_receive_correct_message_btn_clicked)

        self.receive_incorrect_message_btn = QPushButton("Некорректное")
        self.receive_incorrect_message_btn.setFont(general_font)
        self.receive_incorrect_message_btn.clicked.connect(self.on_receive_incorrect_message_btn_clicked)

        self.receive_message_buttons_layout = QHBoxLayout()
        self.receive_message_buttons_layout.addStretch(0)
        self.receive_message_buttons_layout.addWidget(self.receive_correct_message_btn, 0, Qt.AlignmentFlag.AlignCenter)
        self.receive_message_buttons_layout.addWidget(self.receive_incorrect_message_btn, 0, Qt.AlignmentFlag.AlignCenter)
        self.receive_message_buttons_layout.addStretch(0)

        self.receive_message_layout = QVBoxLayout(self.receive_message_frame)
        self.receive_message_layout.addWidget(self.receive_message_label, 0, Qt.AlignmentFlag.AlignCenter)
        self.receive_message_layout.addLayout(self.receive_message_buttons_layout)

        self.status_label = QLabel("Статус")
        self.status_label.setFont(header_font)
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.main_layout = QVBoxLayout(self)
        self.main_layout.addWidget(self.send_message_frame)
        self.main_layout.addWidget(self.receive_message_frame)
        self.main_layout.addWidget(self.status_label, 0, Qt.AlignmentFlag.AlignCenter)
        self.main_layout.addStretch(1)

    def set_colored_message(self, message, color):
        content = f"<span style=\" color:{color};\" >{message}</span>"
        self.status_label.setText(content)

    def on_send_correct_message_btn_clicked(self):
        self.send_message(True)

    def on_send_incorrect_message_btn_clicked(self):
        self.send_message(False)

    def send_message(self, correct):
        message = self.message_box.toPlainText()
        hash = sha256(message.encode())
        signature = rsa.sign(hash.hexdigest().encode(), request.private_key, "SHA-1")

        send_message = message if correct else message + "Что-то не моё"
        self.set_colored_message("Отправленное сообщение: " + message, "#000000")
        self.set_colored_message(self.status_label.text() + "<br>" + "Полученное сервером сообщение: " + send_message, "#000000")

        if request.verify_message(send_message, signature):
            self.set_colored_message(self.status_label.text() + "<br>" + "Сообщение корректно", "#156605")
        else:
            self.set_colored_message(self.status_label.text() + "<br>" + "Сообщение некорректно", "#ff0000")

    def on_receive_correct_message_btn_clicked(self):
        self.receive_message(True)

    def on_receive_incorrect_message_btn_clicked(self):
        self.receive_message(False)

    def receive_message(self, correct):
        json_public_key = request.get_public_key()
        if json_public_key is None:
            self.set_colored_message("Не удалось получить публичный ключ", "#ff0000")
            return

        json_message = request.get_message(correct)
        if json_message is None:
            self.set_colored_message("Не удалось получить сообщение", "#ff0000")
            return

        message = json_message["message"]
        hash = sha256(message.encode()).hexdigest().encode()
        signature = b64decode(json_message["signature"])
        server_public_key = rsa.PublicKey(int(json_public_key["n"]), int(json_public_key["e"]))

        try:
            rsa.verify(hash, signature, server_public_key)

        except rsa.VerificationError:
            self.set_colored_message("Получено некорректное сообщение", "#ff0000")
            return

        self.set_colored_message("Получено корректное сообщение", "#156605")