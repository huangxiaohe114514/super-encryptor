#!/usr/bin/env python3
"""
超级加密工具 - Super Encryptor
功能：选择文件 → 改后缀为.lock → 乱码转换 → 5层加密
算法：AES-256 + XOR + Base64 + 凯撒位移 + 比特反转
"""

import sys
import os
import base64
import hashlib
import struct
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QFileDialog, QProgressBar,
    QMessageBox, QGroupBox, QFormLayout, QDialog, QLineEdit,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# ─────────────────────────────────────────────
#  5 种加密/编码算法
# ─────────────────────────────────────────────

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """XOR 加密：用密钥对数据逐字节异或"""
    out = bytearray(len(data))
    klen = len(key)
    for i, b in enumerate(data):
        out[i] = b ^ key[i % klen]
    return bytes(out)


def base64_encode(data: bytes) -> bytes:
    """Base64 编码"""
    return base64.b64encode(data)


def caesar_shift(data: bytes, shift: int = 7) -> bytes:
    """凯撒位移：对每个字节偏移 shift"""
    return bytes((b + shift) & 0xFF for b in data)


def bit_reverse(data: bytes) -> bytes:
    """比特反转：每个字节的 8 位反转"""
    table = [
        int(f'{b:08b}'[::-1], 2) for b in range(256)
    ]
    return bytes(table[b] for b in data)


def aes_encrypt(data: bytes, key: bytes) -> bytes:
    """AES-256-CBC 加密（带 PKCS7 填充）"""
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(data, AES.block_size)
    return iv + cipher.encrypt(padded)


def aes_decrypt(encrypted: bytes, key: bytes) -> bytes:
    """AES-256-CBC 解密"""
    iv = encrypted[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted[16:])
    return unpad(decrypted, AES.block_size)


# ─────────────────────────────────────────────
#  乱码转换（双向固定映射）
# ─────────────────────────────────────────────

def _build_garble_maps() -> tuple:
    """构建双向乱码映射表：
    - forward: 原始字节值(0-255) -> GBK双字节对
    - reverse: GBK双字节对 -> 原始字节值(0-255)

    使用 GBK 扩展区合法字节对，确保每个输入字节对应唯一且可还原的GBK字符。
    方案：前158个用首字节0x95，后98个用首字节0x96，次字节从0x40递增。
    """
    pairs = []
    # 前158个：首字节 0x95，次字节 0x40-0xFD
    for i in range(158):
        pairs.append((0x95, 0x40 + i))
    # 后98个：首字节 0x96，次字节 0x40-0x9D
    for i in range(98):
        pairs.append((0x96, 0x40 + i))

    assert len(pairs) == 256 and len(set(pairs)) == 256

    forward = {}   # byte -> (byte1, byte2)
    reverse = {}   # (byte1, byte2) -> byte
    for i, (b1, b2) in enumerate(pairs):
        forward[i] = (b1, b2)
        reverse[(b1, b2)] = i

    return forward, reverse


_GARB_FORWARD, _GARB_REVERSE = _build_garble_maps()


def to_garbled(data: bytes) -> bytes:
    """加密：每字节扩展为2字节GBK对，产生乱码效果"""
    result = bytearray(len(data) * 2)
    for i, b in enumerate(data):
        lo, hi = _GARB_FORWARD[b]
        result[i * 2] = lo
        result[i * 2 + 1] = hi
    return bytes(result)


def ungarble(data: bytes) -> bytes:
    """解密：每2字节压缩回1个原始加密字节"""
    if len(data) % 2 != 0:
        data = data[:-1]
    if len(data) % 2 != 0:
        raise ValueError("乱码数据长度错误")
    result = bytearray(len(data) // 2)
    for i in range(0, len(data), 2):
        pair = (data[i], data[i + 1])
        if pair in _GARB_REVERSE:
            result[i // 2] = _GARB_REVERSE[pair]
        else:
            result[i // 2] = data[i]
    return bytes(result)


# ─────────────────────────────────────────────
#  加密核心流程
# ─────────────────────────────────────────────

def generate_key(password: str, salt: bytes) -> bytes:
    """用 PBKDF2 从密码派生 32 字节密钥"""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000, dklen=32)


def super_encrypt(data: bytes, password: str, original_name: str = '') -> bytes:
    """
    加密流程（5 层）：
    1. XOR 加密
    2. AES-256-CBC 加密
    3. Base64 编码
    4. 凯撒位移
    5. 比特反转
    .lock 文件格式：
      [4字节: 原文件名长度] [原文件名 UTF-8] [16字节: salt] [乱码密文]
    """
    salt = get_random_bytes(16)
    key = generate_key(password, salt)

    stage = xor_encrypt(data, key)
    stage = aes_encrypt(stage, key)
    stage = base64_encode(stage)
    stage = caesar_shift(stage)
    stage = bit_reverse(stage)

    name_bytes = original_name.encode('utf-8')
    return struct.pack('>I', len(name_bytes)) + name_bytes + salt + to_garbled(stage)


def super_decrypt(data: bytes, password: str) -> tuple:
    """
    解密：从文件头读取原文件名，恢复乱码字节后逆序执行 5 层算法。
    返回 (原文件名, 解密数据)
    """
    if len(data) < 20:
        raise ValueError("数据过短，不是有效的加密文件")

    name_len = struct.unpack('>I', data[:4])[0]
    orig_name = data[4:4 + name_len].decode('utf-8')
    pos = 4 + name_len

    salt = data[pos:pos + 16]
    key = generate_key(password, salt)
    ciphertext = data[pos + 16:]

    stage = ungarble(ciphertext)

    stage = bit_reverse(stage)
    stage = bytes((b - 7) & 0xFF for b in stage)
    stage = base64.b64decode(stage)
    stage = aes_decrypt(stage, key)
    stage = xor_encrypt(stage, key)
    return orig_name, stage


# ─────────────────────────────────────────────
#  后台加密线程
# ─────────────────────────────────────────────

class EncryptThread(QThread):
    progress = pyqtSignal(int, str)
    finished_sig = pyqtSignal(bool, str)

    def __init__(self, file_path: str, password: str, mode: str):
        super().__init__()
        self.file_path = file_path
        self.password = password
        self.mode = mode

    def run(self):
        try:
            path = Path(self.file_path)

            self.progress.emit(5, f"正在读取文件：{path.name} ...")
            with open(path, 'rb') as f:
                data = f.read()

            if self.mode == 'encrypt':
                self.progress.emit(15, "应用 5 层加密算法并转换乱码 ...")
                encrypted = super_encrypt(data, self.password, path.name)

                new_path = str(path.parent / (path.stem + '.lock'))
                self.progress.emit(70, f"写入文件：{path.stem}.lock ...")
                with open(new_path, 'wb') as f:
                    f.write(encrypted)

                self.progress.emit(85, "删除原始文件 ...")
                os.remove(str(path))

                self.progress.emit(100, "加密完成！")
                self.finished_sig.emit(True, f"文件已加密 → {path.stem}.lock（原文件已删除）")

            else:
                self.progress.emit(15, "尝试解密 ...")
                original_name, decrypted = super_decrypt(data, self.password)

                new_path = str(path.parent / original_name)
                self.progress.emit(80, f"写入文件：{original_name} ...")
                with open(new_path, 'wb') as f:
                    f.write(decrypted)

                self.progress.emit(100, "解密完成！")
                self.finished_sig.emit(True, f"文件已解密 → {original_name}")

        except FileNotFoundError:
            self.finished_sig.emit(False, "错误：文件不存在")
        except Exception as e:
            self.finished_sig.emit(False, f"错误：{e}")


# ─────────────────────────────────────────────
#  密码输入对话框
# ─────────────────────────────────────────────

class PasswordDialog(QDialog):
    def __init__(self, parent=None, mode='encrypt'):
        super().__init__(parent)
        self.setWindowTitle("输入密码" if mode == 'encrypt' else "输入解密密码")
        self.setFixedSize(380, 160)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)
        self.mode = mode

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        hint = "请设置一个强密码，用于保护您的文件。" if mode == 'encrypt' else "请输入正确的解密密码。"
        layout.addWidget(QLabel(hint))

        self.input = QLineEdit(self)
        self.input.setEchoMode(QLineEdit.EchoMode.Password)
        self.input.returnPressed.connect(self.accept)
        layout.addWidget(self.input)

        btn_row = QHBoxLayout()
        ok_btn = QPushButton("确认")
        cancel_btn = QPushButton("取消")
        ok_btn.clicked.connect(self.accept)
        cancel_btn.clicked.connect(self.reject)
        btn_row.addStretch()
        btn_row.addWidget(ok_btn)
        btn_row.addWidget(cancel_btn)
        layout.addLayout(btn_row)

        self.input.setFocus()

    def get_password(self) -> str:
        if self.exec() == QDialog.DialogCode.Accepted:
            return self.input.text()
        return ""


# ─────────────────────────────────────────────
#  主窗口
# ─────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("超级加密工具")
        self.setMinimumSize(600, 520)
        self.current_file = None
        self.is_encrypted_mode = True

        self._apply_stylesheet()

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(16)
        main_layout.setContentsMargins(24, 24, 24, 24)

        # 标题区
        title_layout = QHBoxLayout()
        lock_icon = QLabel("🔐")
        lock_icon.setFont(QFont("Segoe UI Emoji", 28))
        title_layout.addWidget(lock_icon)

        title_text = QVBoxLayout()
        title_label = QLabel("超级加密工具")
        title_label.setFont(QFont("Microsoft YaHei", 18, QFont.Weight.Bold))
        title_label.setStyleSheet("color: #e2e8f0;")
        title_text.addWidget(title_label)

        sub_label = QLabel("5层加密 · 乱码保护 · 安全可靠")
        sub_label.setFont(QFont("Microsoft YaHei", 9))
        sub_label.setStyleSheet("color: #64748b;")
        title_text.addWidget(sub_label)

        title_layout.addStretch()
        title_layout.addLayout(title_text)
        title_layout.addStretch()
        main_layout.addLayout(title_layout)

        # 文件信息区
        self.info_group = QGroupBox("文件信息")
        self.info_group.setStyleSheet(self._group_style())
        info_layout = QFormLayout()
        info_layout.setFormAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_name = QLabel("未选择文件")
        self.lbl_size = QLabel("-")
        self.lbl_algo = QLabel("AES-256-CBC · XOR · Base64 · 凯撒 · 比特反转")
        self.lbl_algo.setStyleSheet("color: #64748b; font-size: 10pt;")
        info_layout.addRow("文件名：", self.lbl_name)
        info_layout.addRow("大小：", self.lbl_size)
        info_layout.addRow("算法：", self.lbl_algo)
        self.info_group.setLayout(info_layout)
        main_layout.addWidget(self.info_group)

        # 按钮区
        btn_row = QHBoxLayout()
        self.btn_select = self._btn("📂  选择文件", "primary")
        self.btn_select.clicked.connect(self.select_file)

        self.btn_action = self._btn("🔒  加密文件", "encrypt")
        self.btn_action.clicked.connect(self.do_action)

        self.btn_clear = self._btn("🗑️  清空", "secondary")
        self.btn_clear.clicked.connect(self.clear_all)

        btn_row.addWidget(self.btn_select)
        btn_row.addWidget(self.btn_action)
        btn_row.addWidget(self.btn_clear)
        main_layout.addLayout(btn_row)

        # 日志区
        log_label = QLabel("操作日志")
        log_label.setFont(QFont("Microsoft YaHei", 9, QFont.Weight.Bold))
        log_label.setStyleSheet("color: #94a3b8; margin-top: 4px;")
        main_layout.addWidget(log_label)

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(120)
        self.log.setFont(QFont("Consolas", 9))
        self.log.setStyleSheet("""
            QTextEdit {
                background: #0d0d1a;
                color: #34d399;
                border: 1px solid #2a2a4a;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        main_layout.addWidget(self.log)

        # 进度条
        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setStyleSheet("""
            QProgressBar {
                border: none;
                border-radius: 6px;
                text-align: center;
                height: 10px;
                background: #1e1e38;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #667eea, stop:1 #a855f7);
                border-radius: 6px;
            }
        """)
        main_layout.addWidget(self.progress)
        main_layout.addStretch()

        self.statusBar().showMessage("就绪 — 请选择要加密或解密的文件")
        self.statusBar().setStyleSheet("color: #64748b; font-size: 11px;")

    def _apply_stylesheet(self):
        self.setStyleSheet("""
            QMainWindow { background: #0f0f1a; }
            QGroupBox {
                background: #16162a;
                border: 1px solid #2a2a4a;
                border-radius: 12px;
                margin-top: 12px;
                padding-top: 10px;
                font-weight: bold;
                color: #94a3b8;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 14px;
                padding: 0 6px;
                color: #64748b;
            }
            QLabel { color: #e2e8f0; }
            QFormLayout QLabel { color: #64748b; }
        """)

    def _group_style(self):
        return """
            QGroupBox {
                background: #16162a;
                border: 1px solid #2a2a4a;
                border-radius: 12px;
                margin-top: 12px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 14px;
                padding: 0 6px;
                color: #64748b;
            }
        """

    def _btn(self, text: str, style: str = "primary") -> QPushButton:
        btn = QPushButton(text)
        btn.setMinimumHeight(44)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        if style == "encrypt":
            btn.setStyleSheet("""
                QPushButton {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 #6d28d9, stop:1 #4c1d95);
                    color: #fff;
                    border: none;
                    border-radius: 10px;
                    font-size: 14px;
                    font-weight: bold;
                    padding: 0 20px;
                }
                QPushButton:hover { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #7c3aed, stop:1 #6d28d9); }
                QPushButton:pressed { background: #5b21b6; }
                QPushButton:disabled { background: #2a2a4a; color: #4a5568; }
            """)
        elif style == "secondary":
            btn.setStyleSheet("""
                QPushButton {
                    background: #1e1e38;
                    color: #94a3b8;
                    border: 1px solid #2a2a4a;
                    border-radius: 10px;
                    font-size: 14px;
                    padding: 0 20px;
                }
                QPushButton:hover { background: #252545; border-color: #3a3a5a; }
                QPushButton:pressed { background: #1a1a30; }
                QPushButton:disabled { color: #3a3a5a; }
            """)
        else:
            btn.setStyleSheet("""
                QPushButton {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 #4f46e5, stop:1 #4338ca);
                    color: #fff;
                    border: none;
                    border-radius: 10px;
                    font-size: 14px;
                    font-weight: bold;
                    padding: 0 20px;
                }
                QPushButton:hover { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #6366f1, stop:1 #4f46e5); }
                QPushButton:pressed { background: #4338ca; }
                QPushButton:disabled { background: #1e1e38; color: #4a5568; border: 1px solid #2a2a4a; }
            """)
        return btn

    def log_msg(self, msg: str):
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        self.log.append(f"[{ts}] {msg}")

    def select_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择文件", "", "所有文件 (*.*);;加密文件 (*.lock)"
        )
        if not path:
            return
        self.current_file = path
        p = Path(path)
        self.is_encrypted_mode = not path.endswith('.lock')

        self.lbl_name.setText(p.name)
        size = p.stat().st_size
        if size > 1024 * 1024:
            self.lbl_size.setText(f"{size / 1024 / 1024:.2f} MB")
        else:
            self.lbl_size.setText(f"{size / 1024:.1f} KB")

        action_text = "🔒  加密文件" if self.is_encrypted_mode else "🔓  解密文件"
        self.btn_action.setText(action_text)

        # 切换按钮样式
        if self.is_encrypted_mode:
            self.btn_action.setStyleSheet("""
                QPushButton {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 #059669, stop:1 #047857);
                    color: #fff; border: none; border-radius: 10px;
                    font-size: 14px; font-weight: bold; padding: 0 20px;
                }
                QPushButton:hover { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #10b981, stop:1 #059669); }
                QPushButton:pressed { background: #047857; }
                QPushButton:disabled { background: #1e1e38; color: #4a5568; }
            """)
        else:
            self.btn_action.setStyleSheet("""
                QPushButton {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 #6d28d9, stop:1 #4c1d95);
                    color: #fff; border: none; border-radius: 10px;
                    font-size: 14px; font-weight: bold; padding: 0 20px;
                }
                QPushButton:hover { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #7c3aed, stop:1 #6d28d9); }
                QPushButton:pressed { background: #5b21b6; }
                QPushButton:disabled { background: #1e1e38; color: #4a5568; }
            """)

        self.log_msg(f"已选择文件：{p.name} ({self.lbl_size.text()})")
        self.statusBar().showMessage(f"已加载：{p.name}")
        self.progress.setValue(0)

    def do_action(self):
        if not self.current_file:
            QMessageBox.warning(self, "提示", "请先选择文件！")
            return

        pwd = PasswordDialog(self, mode='encrypt' if self.is_encrypted_mode else 'decrypt').get_password()
        if not pwd:
            return
        if len(pwd) < 4:
            QMessageBox.warning(self, "提示", "密码长度不能少于 4 位！")
            return

        self.btn_action.setEnabled(False)
        self.btn_select.setEnabled(False)
        self.progress.setValue(0)
        self.log_msg(f"开始{'加密' if self.is_encrypted_mode else '解密'}任务 ...")

        self.thread = EncryptThread(self.current_file, pwd, 'encrypt' if self.is_encrypted_mode else 'decrypt')
        self.thread.progress.connect(self.on_progress)
        self.thread.finished_sig.connect(self.on_finished)
        self.thread.start()

    def on_progress(self, value: int, msg: str):
        self.progress.setValue(value)
        self.log_msg(msg)

    def on_finished(self, success: bool, message: str):
        self.btn_action.setEnabled(True)
        self.btn_select.setEnabled(True)
        self.log_msg(message)
        self.statusBar().showMessage(message)

        if success:
            QMessageBox.information(self, "完成", message)
        else:
            QMessageBox.critical(self, "错误", message)

    def clear_all(self):
        self.current_file = None
        self.lbl_name.setText("未选择文件")
        self.lbl_size.setText("-")
        self.btn_action.setText("🔒  加密文件")
        self.btn_action.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #059669, stop:1 #047857);
                color: #fff; border: none; border-radius: 10px;
                font-size: 14px; font-weight: bold; padding: 0 20px;
            }
            QPushButton:hover { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #10b981, stop:1 #059669); }
            QPushButton:pressed { background: #047857; }
            QPushButton:disabled { background: #1e1e38; color: #4a5568; }
        """)
        self.log.clear()
        self.progress.setValue(0)
        self.statusBar().showMessage("已清空 — 请选择要加密或解密的文件")


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setApplicationName("SuperEncryptor")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
