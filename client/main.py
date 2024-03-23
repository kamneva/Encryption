import sys
from PySide6.QtWidgets import QApplication
from main_window import MainWindow

if __name__ == "__main__":
    app = QApplication([])

    window = MainWindow()
    window.resize(800, 600)
    window.show()

    sys.exit(app.exec())