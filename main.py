"""Application entry point for AD Vigil."""

import sys
from multiprocessing import freeze_support

from PySide6.QtWidgets import QApplication

from gui.main_window import MainWindow
from utils.logger import configure_logging


def main() -> int:
    """Create the Qt application and start the dashboard."""
    configure_logging()
    application = QApplication(sys.argv)
    application.setApplicationName("AD Vigil")
    window = MainWindow()
    window.show()
    return application.exec()


if __name__ == "__main__":
    freeze_support()
    raise SystemExit(main())
