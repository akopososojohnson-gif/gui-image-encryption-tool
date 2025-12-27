import sys
import math
import pathlib
from pathlib import Path
from typing import Optional

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QFileDialog, QMessageBox, QProgressBar
)
from PySide6.QtCore import Qt, QThread, Signal, QMimeData
from PySide6.QtGui import QFont, QDragEnterEvent, QDropEvent, QPixmap, QPainter, QColor, QPen

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import secrets

# ---------- crypto constants ----------
SALT_SIZE = 16
KEY_LEN = 32
NONCE_LEN = 12
CHUNK = 1 << 20  # 1 MB
AAD = b"ImageVault-v1"
MAX_SIZE = 200 * 1024 * 1024  # 200 MB
ALLOWED_EXT = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".enc"}

# ---------- crypto helpers ----------
def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=200_000,
    )
    return kdf.derive(password.encode())

def crypto_stream(in_path: Path, out_path: Path, password: str, encrypt: bool, progress_cb):
    size = in_path.stat().st_size
    if size > MAX_SIZE:
        raise ValueError("File too large")
    chunks = math.ceil(size / CHUNK)

    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        if encrypt:
            salt = secrets.token_bytes(SALT_SIZE)
            nonce = secrets.token_bytes(NONCE_LEN)
            fout.write(salt + nonce)
            aes = AESGCM(_derive_key(password, salt))
        else:
            salt, nonce = fin.read(SALT_SIZE), fin.read(NONCE_LEN)
            aes = AESGCM(_derive_key(password, salt))

        for idx in range(chunks):
            data = fin.read(CHUNK)
            if encrypt:
                out = aes.encrypt(nonce, data, AAD)
            else:
                out = aes.decrypt(nonce, data, AAD)
            fout.write(out)
            progress_cb(int((idx + 1) / chunks * 100))

# ---------- background worker ----------
class CryptoWorker(QThread):
    progress = Signal(int)
    finished = Signal(bool, str)

    def __init__(self, in_path: Path, out_path: Path, password: str, encrypt: bool):
        super().__init__()
        self.in_path, self.out_path, self.pw, self.encrypt = in_path, out_path, password, encrypt

    def run(self):
        try:
            crypto_stream(self.in_path, self.out_path, self.pw, self.encrypt, lambda v: self.progress.emit(v))
            self.finished.emit(True, "Done 👍")
        except Exception as e:
            self.finished.emit(False, str(e))
        finally:
            self.pw = None  # wipe

# ---------- drop zone widget ----------
class DropZone(QLabel):
    dropped = Signal(Path)

    def __init__(self):
        super().__init__("Drop image here or click Browse")
        self.setAlignment(Qt.AlignCenter)
        self.setStyleSheet(
            "QLabel { border: 2px dashed #888; border-radius: 8px; padding: 40px; font-size: 16px; color: #555; }"
            "QLabel:hover { background-color: #f5f5f5; }"
        )
        self.setAcceptDrops(True)

    def dragEnterEvent(self, e: QDragEnterEvent):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e: QDropEvent):
        url = e.mimeData().urls()[0].toLocalFile()
        if url:
            self.dropped.emit(Path(url))

# ---------- main window ----------
class VaultWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Image Vault")
        self.setFixedWidth(600)
        self.setMinimumHeight(500)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setAlignment(Qt.AlignTop)
        layout.setContentsMargins(30, 30, 30, 30)

        # drop zone
        self.drop_zone = DropZone()
        self.drop_zone.dropped.connect(self.set_input_file)
        layout.addWidget(self.drop_zone)

        # browse row
        browse_row = QHBoxLayout()
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.browse_file)
        browse_row.addWidget(self.browse_btn)
        browse_row.addStretch()
        layout.addLayout(browse_row)

        # file info
        self.file_label = QLabel("No file selected")
        self.file_label.setStyleSheet("font-size: 14px;")
        layout.addWidget(self.file_label)

        # password
        self.pw_edit = QLineEdit()
        self.pw_edit.setPlaceholderText("Password (8+ chars)")
        self.pw_edit.setEchoMode(QLineEdit.Password)
        self.pw_edit.textChanged.connect(self.check_ready)
        layout.addWidget(self.pw_edit)

        # strength
        self.strength_label = QLabel("Strength: —")
        layout.addWidget(self.strength_label)

        # progress
        self.progress = QProgressBar()
        self.progress.setTextVisible(True)
        layout.addWidget(self.progress)

        # buttons
        btn_row = QHBoxLayout()
        self.enc_btn = QPushButton("Encrypt")
        self.enc_btn.clicked.connect(self.start_encrypt)
        self.dec_btn = QPushButton("Decrypt")
        self.dec_btn.clicked.connect(self.start_decrypt)
        btn_row.addWidget(self.enc_btn)
        btn_row.addWidget(self.dec_btn)
        layout.addLayout(btn_row)

        # state
        self.in_path: Optional[Path] = None
        self.check_ready()

    # ---------- helpers ----------
    def set_input_file(self, path: Path):
        if path.suffix.lower() not in ALLOWED_EXT:
            QMessageBox.warning(self, "Invalid file", "Only images or .enc files allowed")
            return
        self.in_path = path
        self.file_label.setText(f"{path.name}  ({path.stat().st_size // 1024} KB)")
        self.check_ready()

    def browse_file(self):
        file, _ = QFileDialog.getOpenFileName(
            self,
            "Select image or vault",
            "",
            "Images (*.png *.jpg *.jpeg *.bmp *.gif);;Vault (*.enc);;All (*)",
        )
        if file:
            self.set_input_file(Path(file))

    def check_ready(self):
        pw = self.pw_edit.text()
        ready = bool(self.in_path and pw)
        self.enc_btn.setEnabled(ready)
        self.dec_btn.setEnabled(ready)
        # strength
        if len(pw) < 8:
            self.strength_label.setText("Strength: ❌ too short")
        else:
            self.strength_label.setText("Strength: ✅ ok")

    # ---------- crypto ----------
    def start_encrypt(self):
        if not self.in_path:
            return
        out, _ = QFileDialog.getSaveFileName(
            self,
            "Save encrypted vault",
            self.in_path.with_suffix(".enc").name,
            "Vault (*.enc)",
        )
        if out:
            self.run_worker(Path(out), True)

    def start_decrypt(self):
        if not self.in_path:
            return
        stem = self.in_path.stem.replace("_decrypted", "")
        out, _ = QFileDialog.getSaveFileName(
            self,
            "Save decrypted image",
            stem + "_decrypted.png",
            "Images (*.png *.jpg *.jpeg *.bmp)",
        )
        if out:
            self.run_worker(Path(out), False)

    def run_worker(self, out_path: Path, encrypt: bool):
        self.enc_btn.setEnabled(False)
        self.dec_btn.setEnabled(False)
        self.progress.setValue(0)
        self.worker = CryptoWorker(self.in_path, out_path, self.pw_edit.text(), encrypt)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.finished.connect(self.job_done)
        self.worker.start()

    def job_done(self, ok: bool, msg: str):
        self.worker.quit()
        self.worker.wait()
        self.worker.deleteLater()
        self.enc_btn.setEnabled(True)
        self.dec_btn.setEnabled(True)
        self.pw_edit.clear()
        self.progress.setValue(0)
        (QMessageBox.information if ok else QMessageBox.critical)(self, "Result", msg)

# ---------- entry ----------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))
    win = VaultWindow()
    win.show()
    sys.exit(app.exec())