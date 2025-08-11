#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# =============================================================================
#  ██████╗  ██╗██████╗  ██╗    ██╗███████╗██████╗     ███████╗ █████╗   ███████╗███████╗
# ██╔════╝ ██║██╔══██╗██║    ██║██╔════╝██╔══██╗   ██╔════╝██╔══██╗██╔════╝██╔════╝
# ██║           ██║██████╔╝███████║█████╗    ██████╔╝   ███████╗███████║███████╗███╗  
# ██║           ██║██╔═══╝  ██╔══██║██╔══╝    ██╔══██╗   ╚════██║██╔══██║██╔════╝██╔══╝  
# ╚██████╗ ██║██║          ██║    ██║███████╗██║    ██║   ███████║██║    ██║██║          ███████╗
#   ╚═════╝ ╚═╝╚═╝          ╚═╝    ╚═╝╚══════╝╚═╝    ╚═╝   ╚══════╝╚═╝    ╚═╝╚═╝          ╚══════╝
# =============================================================================
#
#   CipherSafe v1.0 - 初始版本
#
#   作者 (Author):          Hayami-64 & AI
#   版本 (Version):        1.0 (Build 20250809)
#   發佈日期 (Release Date): 2025-08-09
#   授權條款 (License):      MIT License
#   GitHub:              [https://github.com/Hayami-64/CipherSafe]
#
# -----------------------------------------------------------------------------
#
#   描述 (Description):
#
#   CipherSafe 是一款基於 Python 和 PyQt6 的現代檔案/文字加密工具，
#   旨在提供強大且易用的加密功能，保護您的數位資產安全。
#
# -----------------------------------------------------------------------------
#
#   主要功能 (Main Features):
#
#   - **[核心演算法]** 使用 AES-256-GCM 認證加密模式，確保資料的機密性與完整性。
#   - **[金鑰派生]** 使用 Argon2id 演算法從密碼產生金鑰，提供多級可調安全參數，有效抵抗暴力破解。
#   - **[雙重模式]** 支援「金鑰檔案」和「純密碼」兩種加密模式，兼顧最高安全性與便捷性。
#   - **[隱私保護]** 對原始檔名進行加密，防止元資料洩露。
#   - **[使用者體驗]** 提供現代化的圖形使用者介面，支援檔案和資料夾的拖曳操作。
#   - **[輔助工具]** 內建獨立的文字加解密工具和批次重新命名工具。
#
# =============================================================================
#
#   重要聲明與免責條款 (Disclaimer and Limitation of Liability)
#
#   1.  **按「原樣」提供**: 本軟體按「原樣」提供，不附帶任何形式的明示或
#       暗示的保證，包括但不限於對適銷性、特定用途適用性和非侵權性的
#       保證。
#
#   2.  **風險自負**: 您理解並同意，您使用本軟體的風險完全由您自己承擔。
#       作者不對因使用或無法使用本軟體而導致的任何直接、間接、偶然、
#       特殊、懲戒性或後果性損害負責，包括但不限於資料遺失、利潤損失、
#       業務中斷或個人資訊洩露。
#
#   3.  **無資料復原責任**: 作者沒有義務也無法幫助您復原因忘記密碼、
#       遺失金鑰檔案或因軟體錯誤/崩潰而無法存取的資料。**備份您的金鑰、
#       密碼和原始資料是您自己的責任。**
#
#   4.  **合法性與合規性**: 您有責任確保您對本軟體的使用符合您所在國家
#       或地區的法律法規，特別是關於加密軟體使用和資料隱私的規定。
#       作者不對您使用本軟體進行的任何非法活動（如加密勒索、侵犯版權等）
#       承擔任何責任。
#
#   5.  **無技術支援保證**: 作者沒有義務提供任何形式的技術支援、維護或
#       更新。
#
#   透過下載、安裝或使用本軟體，即表示您已閱讀、理解並同意受上述所有
#   條款的約束。如果您不同意這些條款，請不要使用本軟體。
#
# =============================================================================
import sys
import os
import warnings
import subprocess
import shutil
import struct
import uuid
import base64
import logging
import traceback
import re
from io import BytesIO
from typing import Tuple, List, Optional, Dict, Any

try:
    from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                                 QPushButton, QLabel, QFileDialog, QMessageBox,
                                 QProgressBar, QFrame, QCheckBox, QDialog,
                                 QLineEdit, QDialogButtonBox, QMenu, QTextEdit,
                                 QStackedWidget, QComboBox, QRadioButton, QScrollArea,
                                 QSizePolicy)
    from PyQt6.QtCore import Qt, QThread, QObject, pyqtSignal, QSize
    from PyQt6.QtGui import QIcon, QPixmap, QPainter, QAction

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    # FIX: 引入HKDF和SHA256用於從高熵主金鑰派生DEK
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    from argon2.low_level import hash_secret_raw, Type as Argon2Type
    from argon2.exceptions import Argon2Error
except ImportError as e:
    print(f"錯誤：缺少必要的函式庫。請透過 pip 安裝。\n錯誤訊息: {e}")
    print("請執行: pip install PyQt6 cryptography argon2-cffi")
    sys.exit(1)

def resource_path(relative_path):
    """ 獲取資源的絕對路徑，用於封裝後的程式 """
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# --- 日誌設定函式 ---
def setup_logging():
    """設定全域日誌記錄"""
    try:
        # 建立日誌目錄
        log_dir_name = "CipherSafe"
        if sys.platform == "win32":
            log_dir_base = os.path.join(os.environ['LOCALAPPDATA'], log_dir_name)
        elif sys.platform == "darwin":
            log_dir_base = os.path.join(os.path.expanduser('~/Library/Logs'), log_dir_name)
        else: # Linux
            log_dir_base = os.path.join(os.path.expanduser('~/.cache'), log_dir_name)
        
        log_dir = os.path.join(log_dir_base, "logs")
        os.makedirs(log_dir, exist_ok=True)

        log_file = os.path.join(log_dir, 'ciphersafe_log.txt')

        # 使用 RotatingFileHandler 來限制日誌檔案大小
        from logging.handlers import RotatingFileHandler
        handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8')
        
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - [%(threadName)s:%(funcName)s:%(lineno)d] - %(message)s'
        )
        handler.setFormatter(formatter)

        logger = logging.getLogger()
        logger.setLevel(logging.INFO) # 可改為 logging.DEBUG 獲取更詳細資訊
        logger.addHandler(handler)

        return log_file
    except Exception as e:
        print(f"錯誤：無法設定日誌記錄功能。錯誤訊息: {e}")
        return None

# --- 全域異常處理函式 ---
def handle_exception(exc_type, exc_value, exc_traceback):
    """全域異常鉤子，用於捕獲未處理的異常並記錄日誌"""
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    error_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    logging.critical(f"程式意外終止！捕獲到未處理的異常:\n{error_msg}")
    
    try:
        from PyQt6.QtWidgets import QMessageBox
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Icon.Critical)
        msg_box.setWindowTitle("程式發生嚴重錯誤")
        msg_box.setText("CipherSafe 遇到一個無法恢復的錯誤，即將關閉。\n\n"
                        "詳細的錯誤訊息已記錄到日誌檔案中，這對於排查問題非常有幫助。")
        log_file_path = getattr(sys, 'log_file_path', '日誌檔案')
        msg_box.setInformativeText(f"日誌檔案位置: {log_file_path}")
        msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg_box.exec()
    except:
        pass

    logging.shutdown()


warnings.filterwarnings("ignore", category=DeprecationWarning)

# --- 核心加密邏輯 ---
class CryptoLogic:
    _SALT_LEN = 16
    _NONCE_LEN = 12
    _KEY_LEN = 32
    _FILENAME_ENCODING = 'utf-8'
    _FILENAME_ERROR_HANDLER = 'surrogateescape'
    _FNK_LEN = 32
    _WRAPPED_FNK_LEN = _FNK_LEN + 16
    _ARGON2_TYPE = Argon2Type.ID
    # HARDENING: 增強了所有安全等級的Argon2參數
    SECURITY_LEVELS = {
        0: (2, 64 * 1024, 4),    # Low
        1: (3, 256 * 1024, 4),   # Medium (Default)
        2: (4, 512 * 1024, 4),   # High
        3: (4, 1024 * 1024, 6)   # Paranoid
    }
    RECOVERY_COST_MULTIPLIER = (2, 2)
    _TEXT_MAGIC_SIGNATURE = "CSAFE_TEXT_V1"
    _TEXT_ENCODING = 'utf-8'

    # --- CSAFEv3 統一格式常數 ---
    _MAGIC_SIGNATURE = b'CSAFEV03'
    _FILE_TYPE_KEY = b'\x01'
    _FILE_TYPE_DATA = b'\x02'
    _HEADER_LEN = 15 # 8 (magic) + 1 (type) + 2 (meta_len) + 4 (flags)
    _MODE_KEYFILE = b'\x01'
    _MODE_DIRECT_PASS = b'\x02'
    # FIX: 為金鑰包裹操作增加Nonce長度常數
    _WRAP_NONCE_LEN = 12

    class MetaTags:
        TAG_KDF_PARAMS = b'\x00\x01'
        TAG_KDF_SALT_PRIMARY = b'\x00\x02'
        TAG_KDF_SALT_RECOVERY = b'\x00\x03'
        TAG_RECOVERY_QUESTION = b'\x00\x04'
        TAG_WRAPPED_KEY_RECOVERY = b'\x00\x05'
        TAG_ENCRYPTED_FILENAME = b'\x00\x06'
        TAG_FILENAME_NONCE = b'\x00\x07'
        TAG_DATA_NONCE = b'\x00\x08'
        TAG_DATA_DEK_SALT = b'\x00\x09'
        TAG_ENCRYPTION_MODE = b'\x00\x0A'
        # FIX: 為包裹FNK的Nonce新增標籤，解決Nonce重複使用漏洞
        TAG_FNK_WRAP_NONCE = b'\x00\x0B'

    @staticmethod
    def is_valid_csafe_file(file_path: str) -> bool:
        try:
            with open(file_path, 'rb') as f:
                return f.read(8) == CryptoLogic._MAGIC_SIGNATURE
        except (IOError, FileNotFoundError):
            return False

    @staticmethod
    def _derive_key(secret: str, salt: bytes, level: int, is_recovery: bool = False) -> bytes:
        if level not in CryptoLogic.SECURITY_LEVELS: level = 1
        time_cost, memory_cost, parallelism = CryptoLogic.SECURITY_LEVELS[level]
        if is_recovery: time_cost *= CryptoLogic.RECOVERY_COST_MULTIPLIER[0]; memory_cost *= CryptoLogic.RECOVERY_COST_MULTIPLIER[1]
        return hash_secret_raw(secret.encode('utf-8'), salt, time_cost, memory_cost, parallelism, CryptoLogic._KEY_LEN, CryptoLogic._ARGON2_TYPE)

    # FIX: 重構金鑰包裹函式，使用隨機Nonce，返回 nonce + ciphertext
    @staticmethod
    def _wrap_key(master_key: bytes, secret: str, salt: bytes, level: int, is_recovery: bool = False) -> bytes:
        derived_key = CryptoLogic._derive_key(secret, salt, level, is_recovery)
        wrap_nonce = os.urandom(CryptoLogic._WRAP_NONCE_LEN)
        encrypted_key = AESGCM(derived_key).encrypt(wrap_nonce, master_key, None)
        return wrap_nonce + encrypted_key

    # FIX: 重構金鑰解包裹函式，以處理 nonce + ciphertext 格式
    @staticmethod
    def _unwrap_key(wrapped_key: bytes, secret: str, salt: bytes, level: int, is_recovery: bool = False) -> bytes:
        derived_key = CryptoLogic._derive_key(secret, salt, level, is_recovery)
        wrap_nonce = wrapped_key[:CryptoLogic._WRAP_NONCE_LEN]
        encrypted_key = wrapped_key[CryptoLogic._WRAP_NONCE_LEN:]
        return AESGCM(derived_key).decrypt(wrap_nonce, encrypted_key, None)

    # FIX: 修復Nonce重複使用漏洞，函式現在返回包裹FNK時使用的隨機Nonce
    @staticmethod
    def _encrypt_filename(filename_bytes: bytes, master_key: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
        fnk_wrap_nonce = os.urandom(CryptoLogic._NONCE_LEN) # 為包裹FNK產生新Nonce
        fnk = os.urandom(CryptoLogic._FNK_LEN)
        fn_nonce = os.urandom(CryptoLogic._NONCE_LEN)
        # 使用隨機的fnk_wrap_nonce來加密FNK
        wrapped_fnk = AESGCM(master_key).encrypt(fnk_wrap_nonce, fnk, None)
        encrypted_filename = AESGCM(fnk).encrypt(fn_nonce, filename_bytes, None)
        return fnk_wrap_nonce, wrapped_fnk, fn_nonce, encrypted_filename

    # FIX: 修復Nonce重複使用漏洞，函式現在接受fnk_wrap_nonce
    # HARDENING: 改進記憶體安全，使用bytearray並在使用後清除
    @staticmethod
    def _decrypt_filename(wrapped_fnk: bytes, fnk_wrap_nonce: bytes, fn_nonce: bytes, encrypted_filename: bytes, master_key: bytes) -> bytes:
        fnk_bytes = bytearray(AESGCM(master_key).decrypt(fnk_wrap_nonce, wrapped_fnk, None))
        try:
            filename_bytes = AESGCM(fnk_bytes).decrypt(fn_nonce, encrypted_filename, None)
            return filename_bytes
        finally:
            # 確保FNK在使用後立即從記憶體中清除
            fnk_bytes[:] = b'\x00' * len(fnk_bytes)

    @staticmethod
    def _write_meta_block(tag: bytes, value: bytes) -> bytes:
        return tag + len(value).to_bytes(2, 'big') + value

    @staticmethod
    def _parse_metadata(buffer: bytes) -> Dict[bytes, bytes]:
        metadata = {}; i = 0
        while i < len(buffer):
            tag = buffer[i:i+2]
            length = int.from_bytes(buffer[i+2:i+4], 'big')
            value = buffer[i+4:i+4+length]
            metadata[tag] = value
            i += 4 + length
        return metadata

    @staticmethod
    def create_key_file(path: str, password: Optional[str] = None, recovery_data: Optional[Tuple[str, str]] = None, level: int = 1) -> Tuple[bool, str]:
        temp_path = f"{path}.{uuid.uuid4().hex}.tmp"
        # HARDENING: 使用 bytearray 儲存主金鑰，並在使用後擦除
        master_key_ba = bytearray(os.urandom(CryptoLogic._KEY_LEN))
        try:
            meta_buffer = BytesIO()
            wrapped_key = bytes(master_key_ba) # 建立副本用於儲存

            if password and not recovery_data:
                salt = os.urandom(CryptoLogic._SALT_LEN)
                wrapped_key = CryptoLogic._wrap_key(master_key_ba, password, salt, level)
                meta_buffer.write(CryptoLogic._write_meta_block(CryptoLogic.MetaTags.TAG_KDF_PARAMS, level.to_bytes(1, 'big')))
                meta_buffer.write(CryptoLogic._write_meta_block(CryptoLogic.MetaTags.TAG_KDF_SALT_PRIMARY, salt))
            elif password and recovery_data:
                question, answer = recovery_data
                salt1, salt2 = os.urandom(CryptoLogic._SALT_LEN), os.urandom(CryptoLogic._SALT_LEN)
                wrapped_key = CryptoLogic._wrap_key(master_key_ba, password, salt1, level)
                wrapped_by_ans = CryptoLogic._wrap_key(master_key_ba, answer, salt2, level, is_recovery=True)
                meta_buffer.write(CryptoLogic._write_meta_block(CryptoLogic.MetaTags.TAG_KDF_PARAMS, level.to_bytes(1, 'big')))
                meta_buffer.write(CryptoLogic._write_meta_block(CryptoLogic.MetaTags.TAG_KDF_SALT_PRIMARY, salt1))
                meta_buffer.write(CryptoLogic._write_meta_block(CryptoLogic.MetaTags.TAG_KDF_SALT_RECOVERY, salt2))
                meta_buffer.write(CryptoLogic._write_meta_block(CryptoLogic.MetaTags.TAG_RECOVERY_QUESTION, question.encode('utf-8')))
                meta_buffer.write(CryptoLogic._write_meta_block(CryptoLogic.MetaTags.TAG_WRAPPED_KEY_RECOVERY, wrapped_by_ans))

            with open(temp_path, 'wb') as f:
                f.write(CryptoLogic._MAGIC_SIGNATURE)
                f.write(CryptoLogic._FILE_TYPE_KEY)
                meta_bytes = meta_buffer.getvalue()
                f.write(len(meta_bytes).to_bytes(2, 'big'))
                f.write(b'\x00\x00\x00\x00') # Reserved Flags
                f.write(meta_bytes)
                f.write(wrapped_key)
            
            shutil.move(temp_path, path)
            return True, f"金鑰檔案已成功產生於: {path}"
        except Exception as e:
            if os.path.exists(temp_path):
                try: os.remove(temp_path)
                except OSError: pass
            return False, f"產生金鑰檔案失敗: {e}"
        finally:
            # 確保主金鑰在使用後立即從記憶體中清除
            master_key_ba[:] = b'\x00' * len(master_key_ba)

    # --- NEW METHOD FOR PASSWORD RESET ---
    @staticmethod
    def re_wrap_key_file(path: str, master_key: bytearray, new_password: str, level: int) -> Tuple[bool, str]:
        """用新密碼重新包裹一個已存在的主金鑰並覆寫金鑰檔案。"""
        temp_path = f"{path}.{uuid.uuid4().hex}.tmp"
        try:
            meta_buffer = BytesIO()
            
            # 使用新密碼和新鹽來包裹已有的主金鑰
            new_salt = os.urandom(CryptoLogic._SALT_LEN)
            wrapped_key = CryptoLogic._wrap_key(master_key, new_password, new_salt, level)
            
            # 寫入元資料，注意這裡不再有復原相關的資訊
            meta_buffer.write(CryptoLogic._write_meta_block(CryptoLogic.MetaTags.TAG_KDF_PARAMS, level.to_bytes(1, 'big')))
            meta_buffer.write(CryptoLogic._write_meta_block(CryptoLogic.MetaTags.TAG_KDF_SALT_PRIMARY, new_salt))

            with open(temp_path, 'wb') as f:
                f.write(CryptoLogic._MAGIC_SIGNATURE)
                f.write(CryptoLogic._FILE_TYPE_KEY)
                meta_bytes = meta_buffer.getvalue()
                f.write(len(meta_bytes).to_bytes(2, 'big'))
                f.write(b'\x00\x00\x00\x00') # Reserved Flags
                f.write(meta_bytes)
                f.write(wrapped_key)
            
            shutil.move(temp_path, path)
            return True, f"金鑰檔案已成功使用新密碼更新於: {path}"
        except Exception as e:
            if os.path.exists(temp_path):
                try: os.remove(temp_path)
                except OSError: pass
            return False, f"更新金鑰檔案失敗: {e}"

    # FIX: 修復Nonce重複使用漏洞，需要從元資料中讀取新的 FNK_WRAP_NONCE
    @staticmethod
    def get_original_filename(file_path: str, master_key: bytes) -> str:
        try:
            with open(file_path, 'rb') as f:
                if f.read(8) != CryptoLogic._MAGIC_SIGNATURE: return ""
                f.read(1) # type
                meta_len = int.from_bytes(f.read(2), 'big')
                f.read(4) # flags
                meta = CryptoLogic._parse_metadata(f.read(meta_len))
                wrapped_fnk = f.read(CryptoLogic._WRAPPED_FNK_LEN)
                
                # 讀取包裹FNK時使用的Nonce
                fnk_wrap_nonce = meta[CryptoLogic.MetaTags.TAG_FNK_WRAP_NONCE]
                fn_nonce = meta[CryptoLogic.MetaTags.TAG_FILENAME_NONCE]
                encrypted_filename = meta[CryptoLogic.MetaTags.TAG_ENCRYPTED_FILENAME]
                
                original_filename_bytes = CryptoLogic._decrypt_filename(wrapped_fnk, fnk_wrap_nonce, fn_nonce, encrypted_filename, master_key)
                return original_filename_bytes.decode(CryptoLogic._FILENAME_ENCODING, CryptoLogic._FILENAME_ERROR_HANDLER)
        except (InvalidTag, ValueError, KeyError): return ""
        except Exception: return ""

    @staticmethod
    def encrypt_text(plaintext: str, key: bytes, salt: bytes, level: int) -> str:
        try:
            nonce = os.urandom(CryptoLogic._NONCE_LEN)
            aead = AESGCM(key)
            ciphertext = aead.encrypt(nonce, plaintext.encode(CryptoLogic._TEXT_ENCODING), None)
            return ":".join([
                CryptoLogic._TEXT_MAGIC_SIGNATURE,
                str(level),
                base64.b64encode(salt).decode('ascii'),
                base64.b64encode(nonce).decode('ascii'),
                base64.b64encode(ciphertext).decode('ascii')
            ])
        except Exception as e:
            raise RuntimeError(f"文字加密失敗: {e}")

    @staticmethod
    def decrypt_text(encrypted_text: str, key: bytes) -> str:
        try:
            parts = encrypted_text.strip().split(':')
            if len(parts) != 5 or parts[0] != CryptoLogic._TEXT_MAGIC_SIGNATURE:
                raise ValueError("加密文字格式無效或不受支援。")
            nonce = base64.b64decode(parts[3])
            ciphertext = base64.b64decode(parts[4])
            if len(nonce) != CryptoLogic._NONCE_LEN:
                raise ValueError("加密文字元件長度不正確。")
            aead = AESGCM(key)
            plaintext_bytes = aead.decrypt(nonce, ciphertext, None)
            return plaintext_bytes.decode(CryptoLogic._TEXT_ENCODING)
        except (ValueError, InvalidTag, TypeError, IndexError, base64.binascii.Error) as e:
            raise InvalidTag(f"解密失敗：金鑰/密碼錯誤或文字已毀損。({e})")
        except Exception as e:
            raise RuntimeError(f"文字解密時發生未知錯誤: {e}")

# --- Dialogs and Workers ---
class KDFWorker(QObject):
    finished = pyqtSignal(object, object)
    def __init__(self, *args): super().__init__(); self.args = args
    def run(self):
        try:
            # HARDENING: 返回 bytearray 以便後續擦除
            key_bytes = CryptoLogic._unwrap_key(*self.args)
            self.finished.emit(bytearray(key_bytes), None)
        except Exception as e:
            self.finished.emit(None, e)

class MasterKeyDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent); self.result: Dict[str, Any] = {"key": None, "new_password": None, "level": 1, "cancelled": False}; self.key_info = {}; self.thread = None; self.worker = None
        self.setWindowTitle("金鑰驗證"); self.setMinimumWidth(400); self.main_layout = QVBoxLayout(self); self.stacked_widget = QStackedWidget(); self.main_layout.addWidget(self.stacked_widget)
        self._create_password_page(); self._create_recovery_page(); self._create_reset_page()

    def _load_key_data(self, path):
        self.path = path
        try:
            if not CryptoLogic.is_valid_csafe_file(path):
                raise ValueError("這不是一個有效的 CipherSafe 金鑰檔案。")
            
            with open(path, 'rb') as f:
                f.seek(8) # magic
                if f.read(1) != CryptoLogic._FILE_TYPE_KEY: raise ValueError("檔案類型錯誤，不是金鑰檔案。")
                meta_len = int.from_bytes(f.read(2), 'big')
                f.read(4) # flags
                self.key_info['metadata'] = CryptoLogic._parse_metadata(f.read(meta_len))
                self.key_info['wrapped_key'] = f.read()
            
            if not self.key_info['metadata']:
                self.key_info['type'] = 'unencrypted'
            elif CryptoLogic.MetaTags.TAG_RECOVERY_QUESTION in self.key_info['metadata']:
                self.key_info['type'] = 'recoverable'
                question = self.key_info['metadata'][CryptoLogic.MetaTags.TAG_RECOVERY_QUESTION].decode('utf-8')
                self.recovery_question_label.setText(f"<b>復原問題:</b><br>{question}")
            else:
                self.key_info['type'] = 'encrypted'
            
            if CryptoLogic.MetaTags.TAG_KDF_PARAMS in self.key_info['metadata']:
                self.result['level'] = int.from_bytes(self.key_info['metadata'][CryptoLogic.MetaTags.TAG_KDF_PARAMS], 'big')
            return True
        except Exception as e:
            QMessageBox.critical(self, "讀取錯誤", f"讀取金鑰檔案時發生錯誤：\n{e}")
            return False

    def on_password_submit(self):
        password = self.password_input.text()
        wrapped_key = self.key_info['wrapped_key']
        salt = self.key_info['metadata'][CryptoLogic.MetaTags.TAG_KDF_SALT_PRIMARY]
        self._start_kdf_worker(wrapped_key, password, salt, self.result['level'], False)

    def on_answer_submit(self):
        answer = self.answer_input.text()
        wrapped_key = self.key_info['metadata'][CryptoLogic.MetaTags.TAG_WRAPPED_KEY_RECOVERY]
        salt = self.key_info['metadata'][CryptoLogic.MetaTags.TAG_KDF_SALT_RECOVERY]
        self._start_kdf_worker(wrapped_key, answer, salt, self.result['level'], True)

    def on_forgot_password(self):
        if self.key_info.get('type') == 'recoverable':
            self.stacked_widget.setCurrentWidget(self.recovery_page)
        else:
            QMessageBox.information(self, "無復原功能", "此金鑰檔案未設定密碼復原功能。")

    @staticmethod
    def get_key(path, parent=None) -> Optional[Dict[str, Any]]:
        dialog = MasterKeyDialog(parent)
        if not dialog._load_key_data(path): return None
        if dialog.key_info['type'] == 'unencrypted':
            # HARDENING: 返回 bytearray
            dialog.result["key"] = bytearray(dialog.key_info['wrapped_key'])
            return dialog.result
        
        dialog.stacked_widget.setCurrentWidget(dialog.password_page)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            if dialog.result.get("cancelled", False):
                return None
            return dialog.result
        return None
    
    def _start_kdf_worker(self, *args):
        self.set_ui_busy(True); self.thread = QThread(); self.worker = KDFWorker(*args); self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run); self.worker.finished.connect(self.on_kdf_finished); self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater); self.thread.finished.connect(self.thread.deleteLater); self.thread.start()
    
    def on_kdf_finished(self, key, error):
        self.set_ui_busy(False)
        if error:
            logging.error(f"KDF 金鑰派生失敗。錯誤類型: {type(error).__name__}, 錯誤訊息: {error}")
            if isinstance(error, InvalidTag): QMessageBox.warning(self, "驗證失敗", "密碼或答案不正確，請重試。")
            else: QMessageBox.critical(self, "未知錯誤", f"驗證過程中發生錯誤: {error}")
            return
        logging.info("KDF 金鑰派生成功。")
        self.result["key"] = key
        if self.stacked_widget.currentWidget() == self.password_page: self.accept()
        elif self.stacked_widget.currentWidget() == self.recovery_page: self.stacked_widget.setCurrentWidget(self.reset_page)
    
    def set_ui_busy(self, busy):
        for btn in self.findChildren(QPushButton): btn.setEnabled(not busy)
        if busy: QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        else: QApplication.restoreOverrideCursor()
    def _create_password_page(self):
        self.password_page = QWidget(); layout = QVBoxLayout(self.password_page); layout.addWidget(QLabel("請輸入金鑰的主密碼："))
        self.password_input = QLineEdit(); self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.show_password_checkbox = QCheckBox("顯示密碼"); self.show_password_checkbox.toggled.connect(lambda c: self.password_input.setEchoMode(QLineEdit.EchoMode.Normal if c else QLineEdit.EchoMode.Password))
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.forgot_btn = buttons.addButton("忘記密碼?", QDialogButtonBox.ButtonRole.HelpRole)
        buttons.accepted.connect(self.on_password_submit); buttons.rejected.connect(self.reject); self.forgot_btn.clicked.connect(self.on_forgot_password)
        layout.addWidget(self.password_input); layout.addWidget(self.show_password_checkbox, 0, Qt.AlignmentFlag.AlignRight); layout.addWidget(buttons); self.stacked_widget.addWidget(self.password_page)
    def _create_recovery_page(self):
        self.recovery_page = QWidget(); layout = QVBoxLayout(self.recovery_page); self.recovery_question_label = QLabel("..."); self.recovery_question_label.setWordWrap(True)
        layout.addWidget(self.recovery_question_label); layout.addWidget(QLabel("請輸入您的答案:")); self.answer_input = QLineEdit()
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.on_answer_submit); buttons.rejected.connect(self.reject)
        layout.addWidget(self.answer_input); layout.addWidget(buttons); self.stacked_widget.addWidget(self.recovery_page)
    def _create_reset_page(self):
        self.reset_page = QWidget(); layout = QVBoxLayout(self.reset_page); layout.addWidget(QLabel("<b>復原成功！</b>\n現在請重設您的主密碼："))
        self.new_password_input = QLineEdit(); self.new_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.show_new_password_checkbox = QCheckBox("顯示密碼"); self.show_new_password_checkbox.toggled.connect(lambda c: self.new_password_input.setEchoMode(QLineEdit.EchoMode.Normal if c else QLineEdit.EchoMode.Password))
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.on_reset_submit); buttons.rejected.connect(self.on_reset_cancel)
        layout.addWidget(self.new_password_input); layout.addWidget(self.show_new_password_checkbox, 0, Qt.AlignmentFlag.AlignRight); layout.addWidget(buttons); self.stacked_widget.addWidget(self.reset_page)
    def on_reset_submit(self):
        new_password = self.new_password_input.text()
        if not new_password: QMessageBox.warning(self, "密碼為空", "新密碼不能為空，請重新輸入。"); return
        self.result["new_password"] = new_password; self.accept()
    # FIX: 修復復原流程陷阱，取消重設密碼將中止整個操作
    def on_reset_cancel(self):
        QMessageBox.warning(self, "操作已取消", "由於您未設定新密碼，整個操作已被取消。")
        self.result["cancelled"] = True
        self.accept()

class SecurityLevelDialog(QDialog):
    def __init__(self, parent=None, is_direct_mode=False):
        super().__init__(parent)
        prompt = "請為您的新金鑰選擇一組 Argon2 參數。" if not is_direct_mode else "請為您的密碼選擇一組 Argon2 參數。"
        self.setWindowTitle("選擇金鑰派生函數 (KDF) 參數"); self.setMinimumWidth(450); self.level = 1; layout = QVBoxLayout(self)
        layout.addWidget(QLabel(f"{prompt}\n參數越高，安全性越強，但加解密所需時間越長。")); self.combo_box = QComboBox()
        for i, params in CryptoLogic.SECURITY_LEVELS.items(): t, m, p = params; mem_mb = m // 1024; self.combo_box.addItem(f"等級 {i}: 時間成本: {t}, 記憶體成本: {mem_mb}MB, 平行度: {p}")
        self.combo_box.setCurrentIndex(1); buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept); buttons.rejected.connect(self.reject); layout.addWidget(self.combo_box); layout.addWidget(buttons)

    def get_level(self): return self.combo_box.currentIndex()

class SimplePasswordDialog(QDialog):
    def __init__(self, parent=None, prompt="請輸入密碼:"):
        super().__init__(parent); self.setWindowTitle("輸入密碼"); self.setMinimumWidth(350); layout = QVBoxLayout(self)
        self.prompt_label = QLabel(prompt); self.prompt_label.setWordWrap(True); self.password_input = QLineEdit(); self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.show_password_checkbox = QCheckBox("顯示密碼"); self.show_password_checkbox.toggled.connect(lambda c: self.password_input.setEchoMode(QLineEdit.EchoMode.Normal if c else QLineEdit.EchoMode.Password))
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept); buttons.rejected.connect(self.reject)
        layout.addWidget(self.prompt_label); layout.addWidget(self.password_input); layout.addWidget(self.show_password_checkbox, 0, Qt.AlignmentFlag.AlignRight); layout.addWidget(buttons)

    def get_password(self): return self.password_input.text()

class SetupRecoveryDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent); self.setWindowTitle("設定密碼復原"); self.setMinimumWidth(450); layout = QVBoxLayout(self); layout.setSpacing(15)
        warning_frame = QFrame(); warning_frame.setObjectName("WarningFrame"); warning_layout = QHBoxLayout(warning_frame)
        icon_label = QLabel(); icon_pixmap = QPixmap(self.style().standardIcon(QApplication.style().StandardPixmap.SP_MessageBoxWarning).pixmap(32, 32)); icon_label.setPixmap(icon_pixmap)
        warning_text = QLabel("<b>安全警告：復原答案是您資產的最後防線！</b><br>它的安全性低於主密碼，請務必設定一個<b>長且複雜</b>的答案，<br>最好是包含大小寫字母、數字和符號的短語。"); warning_text.setWordWrap(True)
        warning_layout.addWidget(icon_label); warning_layout.addWidget(warning_text); layout.addWidget(warning_frame); layout.addWidget(QLabel("請輸入一個只有您知道答案的問題："))
        self.question_input = QTextEdit(); self.question_input.setPlaceholderText("例如：我童年最喜歡的書是哪一本？"); self.question_input.setFixedHeight(60)
        layout.addWidget(QLabel("請輸入該問題的答案（請牢記）：")); self.answer_input = QLineEdit(); self.answer_input.setPlaceholderText("強烈建議：使用長短語，而非單一詞彙！")
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept); buttons.rejected.connect(self.reject); layout.addWidget(self.question_input); layout.addWidget(self.answer_input); layout.addWidget(buttons)
        self.setStyleSheet("#WarningFrame { background-color: rgba(255, 180, 0, 0.15); border: 1px solid rgba(255, 180, 0, 0.4); border-radius: 5px; }"); self.adjustSize()

    def get_recovery_data(self) -> Optional[Tuple[str, str]]:
        question = self.question_input.toPlainText().strip(); answer = self.answer_input.text().strip()
        if question and answer: return question, answer
        return None

class TextKDFWorker(QObject):
    finished = pyqtSignal(object, object, object, object)
    def __init__(self, password, salt, level):
        super().__init__()
        self.password = password
        self.salt = salt
        self.level = level
    def run(self):
        try:
            key = CryptoLogic._derive_key(self.password, self.salt, self.level)
            self.finished.emit(key, self.salt, self.level, None)
        except Exception as e:
            self.finished.emit(None, None, None, e)

# --- NEW Custom Dialog Base Class ---
class CustomDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.background_pixmap = parent.background_pixmap if hasattr(parent, 'background_pixmap') else None
        if not self.background_pixmap:
            self.setStyleSheet("background-color: #2D2D30;")
        else:
            self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

    def paintEvent(self, event):
        if self.background_pixmap:
            painter = QPainter(self)
            scaled_pixmap = self.background_pixmap.scaled(self.size(), Qt.AspectRatioMode.KeepAspectRatioByExpanding, Qt.TransformationMode.SmoothTransformation)
            x = (self.width() - scaled_pixmap.width()) / 2
            y = (self.height() - scaled_pixmap.height()) / 2
            painter.drawPixmap(int(x), int(y), scaled_pixmap)
        super().paintEvent(event)

    def resizeEvent(self, event):
        self.update()
        super().resizeEvent(event)

# --- MODIFIED TextCryptoDialog to use the new base class ---
class TextCryptoDialog(CustomDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("密碼文字加解密工具")
        self.setMinimumSize(600, 500)
        self.thread = None
        self.worker = None
        self.setObjectName("TextCryptoDialog")
        
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.addWidget(self._create_password_panel())
        io_layout = QHBoxLayout()
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("在此輸入要加密的明文，或要解密的密文...")
        self.output_text = QTextEdit()
        self.output_text.setPlaceholderText("結果將顯示在此處...")
        self.output_text.setReadOnly(True)
        io_layout.addWidget(self.input_text)
        io_layout.addWidget(self.output_text)
        main_layout.addLayout(io_layout)
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setObjectName("StatusLabel")
        main_layout.addWidget(self.status_label)
        action_layout = QHBoxLayout()
        self.encrypt_btn = QPushButton("加密")
        self.encrypt_btn.setObjectName("EncryptButton")
        self.encrypt_btn.clicked.connect(lambda: self.process_text('encrypt'))
        self.decrypt_btn = QPushButton("解密")
        self.decrypt_btn.setObjectName("DecryptButton")
        self.decrypt_btn.clicked.connect(lambda: self.process_text('decrypt'))
        copy_btn = QPushButton("複製結果")
        copy_btn.clicked.connect(self.copy_result)
        action_layout.addStretch()
        action_layout.addWidget(self.encrypt_btn)
        action_layout.addWidget(self.decrypt_btn)
        action_layout.addStretch()
        action_layout.addWidget(copy_btn)
        main_layout.addLayout(action_layout)

    def _create_password_panel(self):
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0,0,0,0)
        pass_layout = QHBoxLayout()
        self.password_label = QLabel("請輸入密碼:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        pass_layout.addWidget(self.password_label)
        pass_layout.addWidget(self.password_input)
        self.show_password_checkbox = QCheckBox("顯示密碼")
        self.show_password_checkbox.toggled.connect(lambda c: self.password_input.setEchoMode(QLineEdit.EchoMode.Normal if c else QLineEdit.EchoMode.Password))
        layout.addLayout(pass_layout)
        layout.addWidget(self.show_password_checkbox, 0, Qt.AlignmentFlag.AlignRight)
        return panel
    def set_ui_busy(self, busy, message=""):
        self.encrypt_btn.setEnabled(not busy)
        self.decrypt_btn.setEnabled(not busy)
        self.password_input.setEnabled(not busy)
        self.status_label.setText(message)
        if busy:
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        else:
            QApplication.restoreOverrideCursor()
    def process_text(self, mode):
        input_data = self.input_text.toPlainText()
        if not input_data:
            QMessageBox.warning(self, "輸入為空", "請輸入要處理的文字。")
            return
        password = self.password_input.text()
        if not password:
            QMessageBox.warning(self, "輸入錯誤", "密碼不能為空。")
            return
        if mode == 'encrypt':
            level_dialog = SecurityLevelDialog(self)
            if level_dialog.exec() != QDialog.DialogCode.Accepted: return
            level = level_dialog.get_level()
            salt = os.urandom(CryptoLogic._SALT_LEN)
            self.set_ui_busy(True, "正在派生金鑰並加密...")
            self.thread = QThread()
            self.worker = TextKDFWorker(password, salt, level)
            self.worker.moveToThread(self.thread)
            self.thread.started.connect(self.worker.run)
            self.worker.finished.connect(self.on_encrypt_kdf_finished)
            self.worker.finished.connect(self.thread.quit)
            self.worker.finished.connect(self.worker.deleteLater)
            self.thread.finished.connect(self.thread.deleteLater)
            self.thread.start()
        else: # decrypt
            try:
                parts = input_data.strip().split(':')
                if len(parts) != 5 or parts[0] != CryptoLogic._TEXT_MAGIC_SIGNATURE:
                    QMessageBox.critical(self, "格式錯誤", "輸入的文字不是有效的 CipherSafe 加密文字格式。")
                    return
                level = int(parts[1])
                salt = base64.b64decode(parts[2])
                self.set_ui_busy(True, "正在派生金鑰...")
                self.thread = QThread()
                self.worker = TextKDFWorker(password, salt, level)
                self.worker.moveToThread(self.thread)
                self.thread.started.connect(self.worker.run)
                self.worker.finished.connect(self.on_decrypt_kdf_finished)
                self.worker.finished.connect(self.thread.quit)
                self.worker.finished.connect(self.worker.deleteLater)
                self.thread.finished.connect(self.thread.deleteLater)
                self.thread.start()
            except (ValueError, TypeError, base64.binascii.Error) as e:
                QMessageBox.critical(self, "操作失敗", f"加密文字格式無效或已毀損。\n錯誤: {e}")
                return
            except Exception as e:
                QMessageBox.critical(self, "未知錯誤", f"處理文字時發生意外錯誤: {e}")
                return
    def on_encrypt_kdf_finished(self, key, salt, level, error):
        self.set_ui_busy(False)
        if error:
            QMessageBox.critical(self, "加密失敗", f"金鑰派生時發生錯誤: {error}")
            return
        try:
            plaintext = self.input_text.toPlainText()
            result = CryptoLogic.encrypt_text(plaintext, key, salt, level)
            self.output_text.setText(result)
        except Exception as e:
            QMessageBox.critical(self, "加密失敗", str(e))
    def on_decrypt_kdf_finished(self, key, salt, level, error):
        self.set_ui_busy(False)
        if error:
            QMessageBox.critical(self, "解密失敗", f"金鑰派生時發生錯誤: {error}")
            return
        try:
            encrypted_text = self.input_text.toPlainText()
            result = CryptoLogic.decrypt_text(encrypted_text, key)
            self.output_text.setText(result)
        except Exception as e:
            self.output_text.clear()
            QMessageBox.critical(self, "解密失敗", str(e))
    def copy_result(self):
        text = self.output_text.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            QMessageBox.information(self, "成功", "結果已複製到剪貼簿。")

# --- NEW ReportDialog Class ---
class ReportDialog(CustomDialog):
    def __init__(self, title, summary, details, output_dir, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(550, 250)
        self.output_dir = output_dir
        self.parent_app = parent

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        top_layout = QHBoxLayout()
        icon_label = QLabel()
        icon_pixmap = QPixmap(self.style().standardIcon(QApplication.style().StandardPixmap.SP_MessageBoxInformation).pixmap(48, 48))
        icon_label.setPixmap(icon_pixmap)
        top_layout.addWidget(icon_label, 0, Qt.AlignmentFlag.AlignTop)

        summary_label = QLabel(summary)
        summary_label.setObjectName("SummaryLabel")
        summary_label.setWordWrap(True)
        top_layout.addWidget(summary_label, 1)
        main_layout.addLayout(top_layout)

        if details:
            scroll = QScrollArea(self)
            scroll.setWidgetResizable(True)
            scroll.setObjectName("ReportScrollArea")
            
            content = QWidget()
            layout = QVBoxLayout(content)
            
            detail_label = QLabel(details)
            detail_label.setWordWrap(True)
            detail_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            detail_label.setAlignment(Qt.AlignmentFlag.AlignTop)
            layout.addWidget(detail_label)
            
            content.setLayout(layout)
            scroll.setWidget(content)
            main_layout.addWidget(scroll, 1) # Add scroll area with stretch factor

        button_layout = QHBoxLayout()
        button_layout.addStretch()
        ok_button = QPushButton("確定")
        ok_button.clicked.connect(self.accept)
        button_layout.addWidget(ok_button)

        if self.output_dir and os.path.exists(self.output_dir):
            open_dir_button = QPushButton("開啟輸出目錄")
            open_dir_button.clicked.connect(self.open_folder)
            button_layout.addWidget(open_dir_button)
        
        main_layout.addLayout(button_layout)

    def open_folder(self):
        if self.parent_app:
            self.parent_app.open_folder(self.output_dir)

class RenameWorker(QObject):
    finished = pyqtSignal(str); progress_update = pyqtSignal(int, int, str)
    def __init__(self, file_list: List[str]):
        super().__init__(); self.file_list = file_list; self._is_running = True
    def stop(self): self._is_running = False
    def run(self):
        total_files = len(self.file_list); renamed_count = 0; errors = []
        for i, old_path in enumerate(self.file_list):
            if not self._is_running: errors.append("操作被使用者中斷。"); break
            base_name = os.path.basename(old_path)
            self.progress_update.emit(i + 1, total_files, base_name)
            try:
                if not os.path.exists(old_path): raise FileNotFoundError("檔案已不存在")
                directory = os.path.dirname(old_path)
                name, ext = os.path.splitext(base_name)
                new_name = uuid.uuid4().hex[:16]
                new_path = os.path.join(directory, new_name + ext)
                if os.path.exists(new_path): new_path = os.path.join(directory, new_name + uuid.uuid4().hex[:4] + ext)
                os.rename(old_path, new_path)
                renamed_count += 1
            except Exception as e: errors.append(f"- {base_name}: {e}")
        report = f"重新命名完成！\n\n成功: {renamed_count}/{total_files} 個檔案。"
        if errors: report += "\n\n失敗或跳過:\n" + "\n".join(errors)
        self.finished.emit(report)

class BatchRenameApp(CustomDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.input_path = ""; self.thread = None; self.worker = None
        self.setWindowTitle("批次重新命名工具"); self.setMinimumSize(480, 350)
        main_layout = QVBoxLayout(self); main_layout.setContentsMargins(20, 20, 20, 20); main_layout.setSpacing(15)
        main_layout.addWidget(QLabel("<b>將檔案/資料夾內的檔名替換為隨機字串</b>"))
        main_layout.addWidget(self._create_file_drop_area())
        self.progress_bar = QProgressBar(); self.progress_bar.setVisible(False); self.progress_bar.setTextVisible(True)
        main_layout.addWidget(self.progress_bar)
        self.start_button = QPushButton("開始重新命名"); self.start_button.setFixedHeight(40); self.start_button.setObjectName("EncryptButton")
        self.start_button.clicked.connect(self.start_renaming)
        main_layout.addWidget(self.start_button)
        self.setAcceptDrops(True)
    def _create_file_drop_area(self):
        widget = QWidget(); layout = QVBoxLayout(widget); layout.setContentsMargins(0, 5, 0, 0)
        self.file_drop_label = QLabel("將檔案或資料夾拖曳至此"); self.file_drop_label.setObjectName("DropLabel"); self.file_drop_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        button_container = QWidget(); button_container.setMinimumWidth(280); btn_layout = QHBoxLayout(button_container); btn_layout.setContentsMargins(0,0,0,0)
        select_file_btn = QPushButton("選擇檔案..."); select_folder_btn = QPushButton("選擇資料夾...")
        select_file_btn.clicked.connect(self.select_file); select_folder_btn.clicked.connect(self.select_folder)
        btn_layout.addWidget(select_file_btn); btn_layout.addWidget(select_folder_btn)
        layout.addWidget(self.file_drop_label); layout.addWidget(button_container, 0, Qt.AlignmentFlag.AlignHCenter)
        return widget
    def start_renaming(self):
        if not self.input_path: QMessageBox.warning(self, "輸入錯誤", "請先選擇檔案或資料夾。"); return
        file_list = []
        if os.path.isdir(self.input_path):
            for root, _, files in os.walk(self.input_path):
                for file in files: file_list.append(os.path.join(root, file))
        else: file_list.append(self.input_path)
        if not file_list: QMessageBox.information(self, "提示", "所選位置沒有檔案可供重新命名。"); return
        self.set_ui_enabled(False)
        self.thread = QThread(); self.worker = RenameWorker(file_list); self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run); self.worker.finished.connect(self.on_finished)
        self.worker.progress_update.connect(self.update_progress); self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater); self.thread.finished.connect(self.thread.deleteLater); self.thread.start()
    def on_finished(self, report):
        self.set_ui_enabled(True); self.progress_bar.setFormat("操作完成")
        report_dialog = ReportDialog("操作報告", report, "", "", self)
        report_dialog.exec()
        self.thread = None; self.worker = None
    def update_progress(self, current, total, filename):
        self.progress_bar.setRange(0, total); self.progress_bar.setValue(current); self.progress_bar.setFormat(f"處理中: {current}/{total}")
    def set_ui_enabled(self, enabled):
        self.progress_bar.setVisible(not enabled); self.start_button.setEnabled(enabled)
        if enabled: self.progress_bar.setValue(0)
    def update_input_path(self, path):
        self.input_path = path; is_dir = os.path.isdir(path) if path else False; name = os.path.basename(path) if path else ""
        text = f"<b>已選{'資料夾' if is_dir else '檔案'}:</b><br>{name}" if path else "將檔案或資料夾拖曳至此"
        self.file_drop_label.setText(text)
    def select_file(self): fname, _ = QFileDialog.getOpenFileName(self, '選擇檔案', '', '所有檔案 (*.*)'); self.update_input_path(fname) if fname else None
    def select_folder(self): dname = QFileDialog.getExistingDirectory(self, '選擇資料夾'); self.update_input_path(dname) if dname else None
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls(): event.acceptProposedAction(); self.file_drop_label.setStyleSheet("#DropLabel { border-color: #0078D4; background-color: rgba(0, 120, 212, 0.2); color: white; }")
    def dragLeaveEvent(self, event): self.file_drop_label.setStyleSheet("")
    def dropEvent(self, event):
        self.file_drop_label.setStyleSheet(""); path = event.mimeData().urls()[0].toLocalFile(); self.update_input_path(path)

class Worker(QObject):
    finished = pyqtSignal(str, str, list); progress_update = pyqtSignal(int, int, str)
    _CHUNK_SIZE = 1024 * 1024; _TAG_LEN = 16
    def __init__(self, mode: str, file_list: List[str], output_dir: str, master_key: bytearray, source_base_path: str, **kwargs):
        super().__init__()
        self.mode, self.file_list, self.output_dir = mode, file_list, output_dir
        self.master_key, self.source_base_path = master_key, source_base_path
        self.ext, self._is_running = '.0721', True
        self.encryption_mode = kwargs.get('encryption_mode')
        self.level = kwargs.get('level', 1)
        self.salt = kwargs.get('salt', None)
        self.total_files_to_process = len(file_list)

    def stop(self): self._is_running = False

    @staticmethod
    def _sanitize_filename(filename: str) -> str:
        """清理檔名，移除非法字元和潛在的危險序列"""
        if not filename:
            return ""
        sanitized = re.sub(r'[/\\]', '', filename)
        sanitized = re.sub(r'[<>:"|?*]', '_', sanitized)
        sanitized = "".join(c for c in sanitized if ord(c) > 31)
        if sys.platform == "win32":
            RESERVED_NAMES = ('CON', 'PRN', 'AUX', 'NUL', 
                              'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
                              'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9')
            name_part, _, _ = sanitized.partition('.')
            if name_part.upper() in RESERVED_NAMES:
                sanitized = f"_{sanitized}_"
        if sanitized in ('.', '..'):
            sanitized = f"_{sanitized}_"
        return sanitized.strip()[:255]

    def run(self):
        errors, successful_paths, skipped_paths = [], [], []
        logging.info(f"Worker 執行緒開始執行。模式: {self.mode}, 檔案數: {self.total_files_to_process}")
        try:
            for i, input_path in enumerate(self.file_list):
                if not self._is_running:
                    logging.info("操作被使用者中斷。")
                    errors.append("操作被使用者中斷。"); break
                
                current_filename = os.path.basename(input_path)
                self.progress_update.emit(i + 1, self.total_files_to_process, current_filename)
                logging.info(f"正在處理檔案 {i+1}/{self.total_files_to_process}: {current_filename}")
                output_path = None
                try:
                    if not os.path.exists(input_path): raise FileNotFoundError(f"來源檔案不存在: {input_path}")

                    is_csafe_file = CryptoLogic.is_valid_csafe_file(input_path)

                    if self.mode == 'encrypt':
                        if is_csafe_file:
                            skipped_paths.append(input_path)
                            errors.append(f"- {current_filename}: 已是加密檔案，已跳過。")
                            logging.warning(f"檔案 '{current_filename}' 已是加密檔案，跳過處理。")
                            continue
                    else: # decrypt mode
                        if not is_csafe_file:
                            skipped_paths.append(input_path)
                            errors.append(f"- {current_filename}: 不是有效的加密檔案，已跳過。")
                            logging.warning(f"檔案 '{current_filename}' 不是有效的加密檔案，跳過處理。")
                            continue

                    relative_path = os.path.relpath(os.path.dirname(input_path), self.source_base_path)
                    if relative_path == '.': relative_path = ''
                    
                    if self.mode == 'encrypt':
                        output_filename = os.path.splitext(current_filename)[0] + self.ext
                        final_output_dir = os.path.join(self.output_dir, relative_path)
                        os.makedirs(final_output_dir, exist_ok=True)
                        output_path = os.path.join(final_output_dir, output_filename)
                        logging.info(f"加密檔案 '{input_path}' 到 '{output_path}'")
                        self._encrypt_file(input_path, output_path)
                    else: # decrypt
                        untrusted_filename = CryptoLogic.get_original_filename(input_path, self.master_key)
                        if not untrusted_filename: raise ValueError("無法讀取原始檔名 (可能金鑰/密碼錯誤或檔案毀損)")
                        
                        output_filename = self._sanitize_filename(os.path.basename(untrusted_filename))
                        if not output_filename:
                            raise ValueError(f"偵測到無效或惡意的原始檔名 (清理後為空): {untrusted_filename}")

                        final_output_dir = os.path.join(self.output_dir, relative_path)
                        os.makedirs(final_output_dir, exist_ok=True)
                        output_path = os.path.join(final_output_dir, output_filename)
                        
                        if os.path.exists(output_path):
                            base, ext = os.path.splitext(output_path)
                            count = 1
                            while os.path.exists(f"{base} ({count}){ext}"):
                                count += 1
                            output_path = f"{base} ({count}){ext}"
                            rename_msg = f"- {current_filename}: 輸出檔案已存在，已自動重新命名為 {os.path.basename(output_path)}"
                            logging.warning(rename_msg)
                            errors.append(rename_msg)

                        logging.info(f"解密檔案 '{input_path}' 到 '{output_path}'")
                        self._decrypt_file(input_path, output_path)

                    if not self._is_running: raise InterruptedError("操作在檔案處理後被中斷")
                    successful_paths.append(input_path)
                    logging.info(f"檔案 '{current_filename}' 處理成功。")

                except (InvalidTag, ValueError) as e:
                    logging.warning(f"檔案 '{current_filename}' 處理失敗: 金鑰/密碼錯誤或檔案毀損。錯誤: {e}")
                    errors.append(f"- {current_filename}: 金鑰/密碼錯誤或檔案已毀損。")
                except Exception as e:
                    logging.error(f"處理檔案 '{current_filename}' 時發生未知系統錯誤。", exc_info=True)
                    if not self._is_running and output_path and os.path.exists(output_path):
                        try: os.remove(output_path); errors.append(f"- {current_filename}: 操作被中斷，殘留檔案已清理。")
                        except OSError: errors.append(f"- {current_filename}: 操作被中斷，但清理殘留檔案失敗。")
                    else:
                        errors.append(f"- {current_filename}: 處理時發生未知系統錯誤。")
        finally:
            if self.master_key:
                self.master_key[:] = b'\x00' * len(self.master_key)
                logging.info("Worker 執行緒中的主金鑰已從記憶體中擦除。")
        
        logging.info("Worker 執行緒執行完畢。")
        
        attempted_files = self.total_files_to_process - len(skipped_paths)
        report = f"操作完成！\n\n成功處理: {len(successful_paths)} / {attempted_files} 個目標檔案。"
        if len(skipped_paths) > 0:
            report += f" ({len(skipped_paths)} 個檔案因類型不符被跳過)"

        if errors: report += "\n\n以下檔案處理失敗或出現警告:\n" + "\n".join(errors)
        
        output_dir_to_open = self.output_dir if successful_paths else ""
        self.finished.emit(report, output_dir_to_open, successful_paths)

    def _encrypt_file(self, input_path, output_path):
        meta_buffer = BytesIO()
        original_filename_bytes = os.path.basename(input_path).encode(CryptoLogic._FILENAME_ENCODING, CryptoLogic._FILENAME_ERROR_HANDLER)
        
        fnk_wrap_nonce, wrapped_fnk, fn_nonce, encrypted_filename = CryptoLogic._encrypt_filename(original_filename_bytes, self.master_key)
        
        dek_salt = os.urandom(CryptoLogic._SALT_LEN)
        initial_data_nonce = os.urandom(CryptoLogic._NONCE_LEN)
        
        hkdf = HKDF(algorithm=hashes.SHA256(), length=CryptoLogic._KEY_LEN, salt=dek_salt, info=b'csafe-data-encryption-key')
        dek_bytes = hkdf.derive(self.master_key)
        dek = bytearray(dek_bytes)
        aead = AESGCM(dek)

        meta_buffer.write(CryptoLogic._write_meta_block(CryptoLogic.MetaTags.TAG_ENCRYPTION_MODE, self.encryption_mode))
        if self.encryption_mode == CryptoLogic._MODE_DIRECT_PASS:
            meta_buffer.write(CryptoLogic._write_meta_block(CryptoLogic.MetaTags.TAG_KDF_PARAMS, self.level.to_bytes(1, 'big')))
            meta_buffer.write(CryptoLogic._write_meta_block(CryptoLogic.MetaTags.TAG_KDF_SALT_PRIMARY, self.salt))
        
        meta_buffer.write(CryptoLogic._write_meta_block(CryptoLogic.MetaTags.TAG_FNK_WRAP_NONCE, fnk_wrap_nonce))
        meta_buffer.write(CryptoLogic._write_meta_block(CryptoLogic.MetaTags.TAG_FILENAME_NONCE, fn_nonce))
        meta_buffer.write(CryptoLogic._write_meta_block(CryptoLogic.MetaTags.TAG_ENCRYPTED_FILENAME, encrypted_filename))
        meta_buffer.write(CryptoLogic._write_meta_block(CryptoLogic.MetaTags.TAG_DATA_DEK_SALT, dek_salt))
        meta_buffer.write(CryptoLogic._write_meta_block(CryptoLogic.MetaTags.TAG_DATA_NONCE, initial_data_nonce))

        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            f_out.write(CryptoLogic._MAGIC_SIGNATURE)
            f_out.write(CryptoLogic._FILE_TYPE_DATA)
            meta_bytes = meta_buffer.getvalue()
            f_out.write(len(meta_bytes).to_bytes(2, 'big'))
            f_out.write(b'\x00\x00\x00\x00')
            f_out.write(meta_bytes)
            f_out.write(wrapped_fnk)
            
            chunk_counter = 0
            while chunk := f_in.read(self._CHUNK_SIZE):
                if not self._is_running: raise InterruptedError("操作在寫入時被中斷")
                
                current_nonce = initial_data_nonce[:4] + chunk_counter.to_bytes(8, 'big')
                f_out.write(aead.encrypt(current_nonce, chunk, None))
                chunk_counter += 1
                
        dek[:] = b'\x00' * len(dek)

    def _decrypt_file(self, input_path, output_path):
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            f_in.seek(8 + 1) # Skip magic + type
            meta_len = int.from_bytes(f_in.read(2), 'big')
            f_in.seek(CryptoLogic._HEADER_LEN)
            meta = CryptoLogic._parse_metadata(f_in.read(meta_len))
            
            dek_salt = meta[CryptoLogic.MetaTags.TAG_DATA_DEK_SALT]
            initial_data_nonce = meta[CryptoLogic.MetaTags.TAG_DATA_NONCE]
            
            hkdf = HKDF(algorithm=hashes.SHA256(), length=CryptoLogic._KEY_LEN, salt=dek_salt, info=b'csafe-data-encryption-key')
            dek_bytes = hkdf.derive(self.master_key)
            dek = bytearray(dek_bytes)
            aead = AESGCM(dek)
            
            f_in.seek(CryptoLogic._HEADER_LEN + meta_len + CryptoLogic._WRAPPED_FNK_LEN)
            
            encrypted_chunk_size = self._CHUNK_SIZE + self._TAG_LEN
            
            chunk_counter = 0
            while True:
                if not self._is_running: raise InterruptedError("操作在解密時被中斷")
                encrypted_chunk = f_in.read(encrypted_chunk_size)
                if not encrypted_chunk: break
                
                current_nonce = initial_data_nonce[:4] + chunk_counter.to_bytes(8, 'big')
                f_out.write(aead.decrypt(current_nonce, encrypted_chunk, None))
                chunk_counter += 1
                
            dek[:] = b'\x00' * len(dek)

class CipherSafeApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setObjectName("CipherSafeApp")
        self.input_path = ""
        self.key_file_path = ""
        self.thread = None
        self.worker = None
        self.current_mode = 'keyfile'
        self.rename_tool_window = None
        self.text_crypto_window = None
        self._is_dragging = False
        self._managed_buttons = []
        self.load_background()
        self.setAcceptDrops(True)
        self.initUI()
        self.apply_styles()

    def initUI(self):
        self.setWindowTitle('CipherSafe v1.0'); self.setMinimumSize(500, 680); self.setGeometry(300, 300, 500, 680)
        icon_path = resource_path('assets/main_icon.ico')
        if os.path.exists(icon_path): self.setWindowIcon(QIcon(icon_path))
        main_layout = QVBoxLayout(self); main_layout.setContentsMargins(25, 20, 25, 25); main_layout.setSpacing(15)
        
        title_layout = QHBoxLayout()
        title_layout.addStretch(1)
        title_label = QLabel("CipherSafe"); title_label.setObjectName("TitleLabel")
        title_layout.addWidget(title_label)
        title_layout.addStretch(1)
        about_btn = QPushButton("關於"); about_btn.setObjectName("AboutButton"); about_btn.setToolTip("查看程式資訊和版權聲明")
        about_btn.setFixedSize(QSize(60, 28)); about_btn.clicked.connect(self.show_about_dialog)
        self._managed_buttons.append(about_btn)
        title_layout.addWidget(about_btn, 0, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop)
        main_layout.addLayout(title_layout)

        main_layout.addWidget(self._create_tools_panel())
        separator = QFrame(); separator.setFrameShape(QFrame.Shape.HLine); separator.setFrameShadow(QFrame.Shadow.Sunken); separator.setObjectName("Separator")
        main_layout.addWidget(separator)

        mode_selector_layout = QHBoxLayout()
        self.keyfile_mode_btn = QPushButton("金鑰檔案模式"); self.keyfile_mode_btn.setCheckable(True); self.keyfile_mode_btn.setChecked(True); self.keyfile_mode_btn.setObjectName("ModeButton")
        self.password_mode_btn = QPushButton("密碼模式"); self.password_mode_btn.setCheckable(True); self.password_mode_btn.setObjectName("ModeButton")
        self._managed_buttons.extend([self.keyfile_mode_btn, self.password_mode_btn])
        mode_selector_layout.addWidget(self.keyfile_mode_btn); mode_selector_layout.addWidget(self.password_mode_btn)
        self.keyfile_mode_btn.clicked.connect(lambda: self.switch_mode('keyfile')); self.password_mode_btn.clicked.connect(lambda: self.switch_mode('password'))
        main_layout.addLayout(mode_selector_layout)
        
        self.mode_stack = QStackedWidget()
        self.mode_stack.addWidget(self._create_keyfile_mode_page()); self.mode_stack.addWidget(self._create_password_mode_page())
        main_layout.addWidget(self.mode_stack)
        
        options_layout = QHBoxLayout(); options_layout.addStretch()
        self.save_to_original_path_checkbox = QCheckBox("儲存到來源路徑"); self.save_to_original_path_checkbox.setObjectName("OptionCheckbox"); self.save_to_original_path_checkbox.setToolTip("勾選後，輸出檔案將儲存在與來源檔案相同的位置。")
        self.delete_source_checkbox = QCheckBox("處理後刪除來源檔案"); self.delete_source_checkbox.setObjectName("OptionCheckbox"); self.delete_source_checkbox.setChecked(False); self.delete_source_checkbox.setToolTip("操作成功後，自動刪除原始檔案或資料夾。\n警告：此操作不可逆，請謹慎使用！")
        options_layout.addWidget(self.save_to_original_path_checkbox); options_layout.addWidget(self.delete_source_checkbox)
        main_layout.addLayout(options_layout)
        
        self.progress_bar = QProgressBar(); self.progress_bar.setVisible(False); self.progress_bar.setTextVisible(True)
        main_layout.addWidget(self.progress_bar)
        
        self.cancel_button = QPushButton("中斷操作"); self.cancel_button.setObjectName("DecryptButton"); self.cancel_button.setFixedHeight(30); self.cancel_button.setToolTip("立即中斷當前所有操作。"); self.cancel_button.clicked.connect(self.cancel_operation); self.cancel_button.setVisible(False)
        main_layout.addWidget(self.cancel_button, 0, Qt.AlignmentFlag.AlignHCenter)
        
        main_layout.addStretch(1); main_layout.addWidget(self._create_operation_panel())
        self.update_input_path(self.input_path)

    def start_operation(self):
        logging.info("開始操作流程...")
        if self.thread and self.thread.isRunning():
            logging.warning("操作請求被拒絕，因為已有任務在執行。")
            QMessageBox.warning(self, "提示", "一個操作正在進行中，請稍候。"); return
        if not self.input_path:
            logging.warning("操作請求被拒絕，因為未選擇輸入路徑。")
            QMessageBox.warning(self, '輸入錯誤', '請先選擇一個檔案或資料夾！'); return
        
        mode = 'encrypt' if self.sender() == self.encrypt_btn else 'decrypt'
        logging.info(f"操作模式: {mode}, 輸入路徑: '{self.input_path}'")
        
        is_dir_mode = os.path.isdir(self.input_path)
        file_list = []; source_base_path = os.path.dirname(self.input_path) if not is_dir_mode else self.input_path
        if is_dir_mode:
            for root, _, files in os.walk(self.input_path):
                for file in files:
                    if not file.lower().endswith('.key'): file_list.append(os.path.join(root, file))
        else: file_list.append(self.input_path)
        
        if not file_list:
            logging.info("選擇的資料夾為空或只包含金鑰檔案，操作中止。")
            QMessageBox.information(self, '提示', '選擇的資料夾為空或只包含金鑰檔案，無需操作。'); return

        if mode == 'decrypt':
            # A quick check on the first file to catch obvious errors early.
            first_file_is_csafe = False
            for f_path in file_list:
                if CryptoLogic.is_valid_csafe_file(f_path):
                    first_file_is_csafe = True
                    break
            if not first_file_is_csafe and not is_dir_mode:
                 QMessageBox.critical(self, "檔案類型錯誤", f"'{os.path.basename(self.input_path)}' 不是一個有效的 CipherSafe 加密檔案。"); return

        output_dir = source_base_path if self.save_to_original_path_checkbox.isChecked() else QFileDialog.getExistingDirectory(self, '選擇輸出目錄', source_base_path)
        if not output_dir: logging.info("使用者取消選擇輸出目錄，操作中止。"); return
        
        master_key, worker_kwargs = None, {}
        if self.current_mode == 'keyfile':
            if not self.key_file_path: QMessageBox.warning(self, '輸入錯誤', '請先選擇一個金鑰檔案！'); return
            key_result = MasterKeyDialog.get_key(self.key_file_path, self)
            if not key_result or not key_result.get("key"): logging.info("使用者取消金鑰驗證或驗證失敗，操作中止。"); return
            master_key = key_result["key"]; worker_kwargs = {'encryption_mode': CryptoLogic._MODE_KEYFILE}
            
            if new_password := key_result.get("new_password"):
                reset_success = self._reset_key_password(master_key, new_password, key_result['level'])
                if not reset_success:
                    logging.warning("金鑰檔案密碼重設失敗或被使用者取消，主操作中止。")
                    self.set_ui_enabled(True)
                    return

        else: # Password mode
            if mode == 'encrypt':
                level_dialog = SecurityLevelDialog(self)
                if level_dialog.exec() != QDialog.DialogCode.Accepted: return
                level = level_dialog.get_level()
                pass_dialog = SimplePasswordDialog(self, "請輸入用於加密的密碼：")
                if pass_dialog.exec() != QDialog.DialogCode.Accepted: return
                password = pass_dialog.get_password()
                if not password: QMessageBox.warning(self, "密碼為空", "密碼不能為空。"); return
                salt = os.urandom(CryptoLogic._SALT_LEN)
                master_key = bytearray(CryptoLogic._derive_key(password, salt, level))
                worker_kwargs = {'encryption_mode': CryptoLogic._MODE_DIRECT_PASS, 'level': level, 'salt': salt}
            else: # Decrypt
                try:
                    # Find the first valid file to read metadata from
                    first_valid_file = None
                    for f_path in file_list:
                        if CryptoLogic.is_valid_csafe_file(f_path):
                            first_valid_file = f_path
                            break
                    if not first_valid_file:
                        QMessageBox.critical(self, "無有效檔案", "在所選目標中找不到任何有效的加密檔案。"); return

                    with open(first_valid_file, 'rb') as f:
                        f.seek(8 + 1)
                        meta_len = int.from_bytes(f.read(2), 'big')
                        f.seek(CryptoLogic._HEADER_LEN)
                        meta = CryptoLogic._parse_metadata(f.read(meta_len))
                        level = int.from_bytes(meta[CryptoLogic.MetaTags.TAG_KDF_PARAMS], 'big')
                        salt = meta[CryptoLogic.MetaTags.TAG_KDF_SALT_PRIMARY]
                except Exception as e:
                    logging.error(f"解密時無法解析檔案參數: {e}", exc_info=True)
                    QMessageBox.critical(self, "檔案毀損", f"無法解析檔案 '{os.path.basename(first_valid_file)}' 的解密參數。"); return
                
                pass_dialog = SimplePasswordDialog(self, "請輸入密碼以解密檔案：")
                if pass_dialog.exec() != QDialog.DialogCode.Accepted: return
                password = pass_dialog.get_password()
                if not password: return
                master_key = bytearray(CryptoLogic._derive_key(password, salt, level))
                worker_kwargs = {'encryption_mode': CryptoLogic._MODE_DIRECT_PASS}

        if not master_key:
            logging.error("未能獲取到主金鑰，操作中止。")
            QMessageBox.critical(self, "內部錯誤", "未能獲取到主金鑰，操作中止。"); return
        
        logging.info("主金鑰已獲取，準備啟動 Worker 執行緒。")
        self.set_ui_enabled(False)
        self.thread = QThread()
        self.worker = Worker(mode, file_list, output_dir, master_key, source_base_path, **worker_kwargs)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.on_operation_finished)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.worker.progress_update.connect(self.update_progress)
        self.thread.start()

    def _reset_key_password(self, master_key: bytearray, new_password: str, level: int) -> bool:
        """
        用新密碼更新金鑰檔案。
        成功返回 True，失敗或使用者取消返回 False。
        此方法不應修改傳入的 master_key。
        """
        logging.info(f"開始重設金鑰檔案 '{self.key_file_path}' 的密碼。")
        try:
            if not self._confirm_overwrite(self.key_file_path):
                logging.info("使用者取消了金鑰檔案覆寫操作。")
                QMessageBox.warning(self, "操作取消", "密碼重設操作已被使用者取消。")
                return False

            success, message = CryptoLogic.re_wrap_key_file(self.key_file_path, master_key, new_password, level)
            
            if success:
                logging.info("金鑰檔案密碼重設成功。")
                QMessageBox.information(self, "密碼已重設", "您的主密碼已成功更新！\n\n重要提示：舊的密碼復原功能已被移除以增強安全性。")
                return True
            else:
                raise RuntimeError(message)
        except Exception as e:
            logging.error(f"重設密碼時寫入金鑰檔案失敗: {e}", exc_info=True)
            QMessageBox.critical(self, "寫入錯誤", f"重設密碼時寫入金鑰檔案失敗：\n{e}")
            return False

    def show_about_dialog(self):
        about_text = """
        <h2>CipherSafe v1.0</h2>
        <p><b>Security Patch</b> (Build 20250809)</p>
        <p>一個專注、易用的密碼學工具，旨在提供強大的檔案和文字加密功能。</p>
        <p><b>作者:</b> Hayami-64 & AI</p>
        <p><b>GitHub:</b> <a href="https://github.com/Hayami-64/CipherSafe">https://github.com/Hayami-64/CipherSafe</a></p>
        <p><b>Bilibili:</b> <a href="https://space.bilibili.com/645321866">Hayami-64 (UID: 645321866)</a></p>
        <p><b>技術棧:</b> Python, PyQt6, Cryptography, Argon2</p>
        <hr>
        <h3>重要聲明與免責條款</h3>
        <p style="font-size: 9pt; color: #AAAAAA;">
            <b>1. 按「原樣」提供:</b> 本軟體按「原樣」提供，不附帶任何形式的明示或
            暗示的保證，包括但不限於對適銷性、特定用途適用性和非侵權性的
            保證。<br><br>
            <b>2. 風險自負:</b> 您理解並同意，您使用本軟體的風險完全由您自己承擔。
            作者不對因使用或無法使用本軟體而導致的任何直接、間接、偶然、
            特殊、懲戒性或後果性損害負責，包括但不限於資料遺失、利潤損失、
            業務中斷或個人資訊洩露。<br><br>
            <b>3. 無資料復原責任:</b> 作者沒有義務也無法幫助您復原因忘記密碼、
            遺失金鑰檔案或因軟體錯誤/崩潰而無法存取的資料。**備份您的金鑰、
            密碼和原始資料是您自己的責任。**<br><br>
            <b>4. 合法性與合規性:</b> 您有責任確保您對本軟體的使用符合您所在國家
            或地區的法律法規，特別是關於加密軟體使用和資料隱私的規定。
            作者不對您使用本軟體進行的任何非法活動（如加密勒索、侵犯版權等）
            承擔任何責任。<br><br>
            <b>5. 無技術支援保證:</b> 作者沒有義務提供任何形式的技術支援、維護或
            更新。<br><br>
            <b>透過下載、安裝或使用本軟體，即表示您已閱讀、理解並同意受上述所有
            條款的約束。如果您不同意這些條款，請不要使用本軟體。</b>
        </p>
        <hr>
        <p style="font-size: 9pt;"><i>本專案基於 MIT 授權條款開源。</i></p>
        """
        dialog = ReportDialog("關於 CipherSafe", about_text, "", "", self)
        dialog.setMinimumSize(500, 400)
        dialog.exec()

    def _create_tools_panel(self):
        tools_frame = QFrame()
        tools_layout = QHBoxLayout(tools_frame)
        tools_layout.setContentsMargins(0, 0, 0, 0)
        tools_layout.setSpacing(10)
        tools_label = QLabel("工具:")
        tools_label.setObjectName("ToolsLabel")
        text_crypto_btn = QPushButton("文字加解密")
        text_crypto_btn.setToolTip("開啟一個新視窗，用於加密或解密文字內容。")
        text_crypto_btn.clicked.connect(self.show_text_crypto_tool)
        rename_btn = QPushButton("批次重新命名")
        rename_btn.setToolTip("將選定檔案或資料夾內的所有檔名替換為隨機字串。")
        rename_btn.clicked.connect(self.show_batch_rename_tool)
        self._managed_buttons.extend([text_crypto_btn, rename_btn])
        tools_layout.addWidget(tools_label)
        tools_layout.addStretch(1)
        tools_layout.addWidget(text_crypto_btn)
        tools_layout.addWidget(rename_btn)
        return tools_frame

    def show_batch_rename_tool(self):
        if self.rename_tool_window is None or not self.rename_tool_window.isVisible():
            self.rename_tool_window = BatchRenameApp(self)
            self.rename_tool_window.show()

    def show_text_crypto_tool(self):
        if self.text_crypto_window is None or not self.text_crypto_window.isVisible():
            self.text_crypto_window = TextCryptoDialog(self)
            self.text_crypto_window.show()

    def switch_mode(self, mode):
        self.current_mode = mode
        if mode == 'keyfile': self.keyfile_mode_btn.setChecked(True); self.password_mode_btn.setChecked(False); self.mode_stack.setCurrentIndex(0)
        else: self.keyfile_mode_btn.setChecked(False); self.password_mode_btn.setChecked(True); self.mode_stack.setCurrentIndex(1)
        self.update_input_path("")

    def _create_keyfile_mode_page(self):
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(0,0,0,0); layout.setSpacing(15)
        layout.addWidget(self._create_step_widget("1", "選擇檔案或資料夾", self._create_file_drop_area()))
        layout.addWidget(self._create_step_widget("2", "選擇或產生金鑰", self._create_key_file_panel()))
        return page

    def _create_password_mode_page(self):
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(0,0,0,0); layout.setSpacing(15)
        layout.addWidget(self._create_step_widget("1", "選擇檔案或資料夾", self._create_file_drop_area(is_password_mode=True)))
        spacer_frame = QFrame(); spacer_layout = QVBoxLayout(spacer_frame)
        spacer_layout.addWidget(QLabel("2")); spacer_layout.addWidget(QLabel("密碼將在操作時輸入")); spacer_frame.setVisible(False)
        layout.addWidget(spacer_frame)
        return page

    def on_operation_finished(self, report, output_dir, successful_paths):
        logging.info("操作完成，產生報告。")
        self.set_ui_enabled(True)
        self.progress_bar.setFormat("操作完成")
        
        if self.delete_source_checkbox.isChecked() and successful_paths:
            logging.info("開始刪除來源檔案...")
            
            deleted_count = 0
            deletion_errors = []
            for path in successful_paths:
                try:
                    if os.path.exists(path):
                        os.remove(path)
                        deleted_count += 1
                        logging.info(f"已刪除來源檔案: {path}")
                except OSError as e:
                    error_msg = f"刪除來源檔案失敗: {os.path.basename(path)} ({e})"
                    deletion_errors.append(error_msg)
                    logging.error(error_msg)
            
            if deleted_count > 0:
                report += f"\n\n已成功刪除 {deleted_count} 個來源檔案。"
            if deletion_errors:
                report += "\n\n刪除時發生錯誤:\n" + "\n".join(deletion_errors)

            is_dir_mode = os.path.isdir(self.input_path)
            if is_dir_mode:
                try:
                    for dirpath, dirnames, filenames in os.walk(self.input_path, topdown=False):
                        if not dirnames and not filenames:
                            os.rmdir(dirpath)
                            logging.info(f"已刪除空目錄: {dirpath}")
                except OSError as e:
                    logging.warning(f"刪除來源資料夾中的空目錄失敗: {e}")
            
            if not os.path.exists(self.input_path):
                self.update_input_path("")

        # --- USE NEW CUSTOM REPORT DIALOG ---
        report_lines = report.split('\n\n')
        summary = report_lines[0]
        details = "\n\n".join(report_lines[1:])
        
        dialog = ReportDialog("操作報告", summary, details, output_dir, self)
        dialog.exec()

        self.thread = None
        self.worker = None

    def load_background(self):
        self.background_pixmap = None
        for ext in ['jpg', 'png']:
            path = resource_path(f'assets/background.{ext}')
            if os.path.exists(path): self.background_pixmap = QPixmap(path); break

    def _create_step_widget(self, number, title, content_widget):
        frame = QFrame(); layout = QHBoxLayout(frame); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(15)
        num_label = QLabel(number); num_label.setObjectName("StepNumber"); num_label.setFixedSize(30, 30); num_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        if number == " ": num_label.setStyleSheet("background-color: transparent;")
        content_layout = QVBoxLayout(); title_label = QLabel(title); title_label.setObjectName("StepTitle")
        content_layout.addWidget(title_label); content_layout.addWidget(content_widget)
        layout.addWidget(num_label); layout.addLayout(content_layout)
        return frame

    def _create_file_drop_area(self, is_password_mode=False):
        widget = QWidget(); layout = QVBoxLayout(widget); layout.setContentsMargins(0, 5, 0, 0)
        drop_label = QLabel("將檔案或資料夾拖曳至此"); drop_label.setObjectName("DropLabel"); drop_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        if is_password_mode: self.password_mode_file_drop_label = drop_label; drop_label.setToolTip("支援拖曳單一檔案或資料夾到此區域。")
        else: self.keyfile_mode_file_drop_label = drop_label; drop_label.setToolTip("支援拖曳單一檔案、資料夾或金鑰檔案到此區域。")
        button_container = QWidget(); button_container.setMinimumWidth(280); btn_layout = QHBoxLayout(button_container); btn_layout.setContentsMargins(0,0,0,0)
        select_file_btn = QPushButton("選擇檔案..."); select_folder_btn = QPushButton("選擇資料夾...")
        self._managed_buttons.extend([select_file_btn, select_folder_btn])
        select_file_btn.setToolTip("點擊以選擇單一檔案進行操作。"); select_folder_btn.setToolTip("點擊以選擇一個資料夾進行批次操作。")
        select_file_btn.clicked.connect(self.select_file); select_folder_btn.clicked.connect(self.select_folder)
        btn_layout.addWidget(select_file_btn); btn_layout.addWidget(select_folder_btn)
        layout.addWidget(drop_label); layout.addWidget(button_container, 0, Qt.AlignmentFlag.AlignHCenter)
        return widget

    def _create_key_file_panel(self):
        widget = QWidget(); layout = QHBoxLayout(widget); layout.setContentsMargins(0, 5, 0, 0); layout.setSpacing(10)
        self.select_key_btn = QPushButton("選擇金鑰檔案...")
        self.select_key_btn.setToolTip("選擇一個已存在的 .key 檔案作為加密/解密的金鑰。")
        self.select_key_btn.clicked.connect(self.select_key_file)
        self.generate_key_menu_btn = QPushButton("產生新金鑰")
        self.generate_key_menu_btn.setToolTip("點擊產生新的金鑰檔案，可選擇是否使用密碼保護。")
        self._managed_buttons.extend([self.select_key_btn, self.generate_key_menu_btn])
        menu = QMenu(self)
        gen_unencrypted_action = QAction("產生金鑰 (無密碼)", self)
        gen_unencrypted_action.triggered.connect(self.generate_key_unencrypted)
        menu.addAction(gen_unencrypted_action)
        password_menu = QMenu("產生帶密碼的金鑰", self)
        gen_encrypted_action = QAction("標準密碼金鑰", self)
        gen_encrypted_action.triggered.connect(self.generate_key_encrypted)
        password_menu.addAction(gen_encrypted_action)
        gen_recoverable_action = QAction("帶復原功能的密碼金鑰", self)
        gen_recoverable_action.triggered.connect(self.generate_key_recoverable)
        password_menu.addAction(gen_recoverable_action)
        menu.addMenu(password_menu)
        self.generate_key_menu_btn.setMenu(menu)
        layout.addWidget(self.select_key_btn)
        layout.addWidget(self.generate_key_menu_btn)
        return widget

    def _create_operation_panel(self):
        widget = QWidget(); main_v_layout = QVBoxLayout(widget); main_v_layout.setContentsMargins(0, 10, 0, 0); main_v_layout.setSpacing(10)
        crypto_layout = QHBoxLayout(); crypto_layout.setSpacing(15)
        self.encrypt_btn = QPushButton("加密"); self.encrypt_btn.setObjectName("EncryptButton")
        self.decrypt_btn = QPushButton("解密"); self.decrypt_btn.setObjectName("DecryptButton")
        self._managed_buttons.extend([self.encrypt_btn, self.decrypt_btn])
        for btn in [self.encrypt_btn, self.decrypt_btn]: btn.setFixedHeight(45); btn.clicked.connect(self.start_operation)
        self.encrypt_btn.setToolTip("使用所選模式加密指定的檔案或資料夾。"); self.decrypt_btn.setToolTip("使用所選模式解密指定的 .0721 檔案或資料夾。")
        crypto_layout.addWidget(self.encrypt_btn); crypto_layout.addWidget(self.decrypt_btn)
        main_v_layout.addLayout(crypto_layout)
        return widget

    def apply_styles(self):
        if not self.background_pixmap:
            self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
            try:
                from ctypes import windll, c_int, byref
                hwnd = self.winId(); value = c_int(2); windll.dwmapi.DwmSetWindowAttribute(hwnd, 38, byref(value), 4)
                self.setStyleSheet(f"QWidget#CipherSafeApp {{ background-color: transparent; }} {self.get_common_stylesheet()}")
            except Exception: self.setStyleSheet(f"QWidget#CipherSafeApp {{ background-color: rgba(30, 30, 30, 0.85); }} {self.get_common_stylesheet()}")
        else: self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False); self.setStyleSheet(self.get_common_stylesheet())

    def get_common_stylesheet(self):
        widget_bg_color = "transparent" if self.background_pixmap else "rgba(0, 0, 0, 0.2)"
        widget_border_color = "rgba(255, 255, 255, 0.3)" if not self.background_pixmap else "transparent"
        text_crypto_dialog_bg = "transparent" if self.background_pixmap else "#2D2D30"
        return f"""
            #CipherSafeApp #TitleLabel {{ font-size: 22pt; font-weight: bold; color: white; padding-bottom: 10px; }}
            #CipherSafeApp #StepTitle, #TextCryptoDialog QLabel, #BatchRenameApp QLabel, ReportDialog QLabel {{ color: #CCCCCC; font-weight: bold; font-size: 11pt; }}
            ReportDialog #SummaryLabel {{ font-size: 12pt; }}
            #TextCryptoDialog #StatusLabel {{ font-size: 9pt; font-style: italic; }}
            #CipherSafeApp #StepNumber {{ background-color: rgba(255, 255, 255, 0.1); color: white; font-size: 14pt; font-weight: bold; border-radius: 15px; }}
            #CipherSafeApp #DropLabel, #BatchRenameApp #DropLabel {{ background-color: {widget_bg_color}; border: 1px dashed {widget_border_color}; border-radius: 8px; min-height: 80px; font-size: 11pt; color: #AAAAAA; }}
            #CipherSafeApp #DropLabel:hover, #BatchRenameApp #DropLabel:hover {{ border-color: rgba(255, 255, 255, 0.7); color: white; }}
            QPushButton, #BatchRenameApp QPushButton, #TextCryptoDialog QPushButton, ReportDialog QPushButton {{ background-color: rgba(255, 255, 255, 0.1); border: 1px solid rgba(255, 255, 255, 0.2); border-radius: 5px; padding: 8px 12px; font-size: 10pt; color: #E0E0E0; min-width: 80px; }}
            QPushButton:hover, #BatchRenameApp QPushButton:hover, #TextCryptoDialog QPushButton:hover, ReportDialog QPushButton:hover {{ background-color: rgba(255, 255, 255, 0.15); border-color: rgba(255, 255, 255, 0.4); }}
            #CipherSafeApp QPushButton#ModeButton {{ padding: 10px; }}
            #CipherSafeApp QPushButton#ModeButton:checked {{ background-color: rgba(0, 120, 212, 0.5); border-color: #0078D4; color: white; }}
            #CipherSafeApp QPushButton::menu-indicator {{ image: none; }}
            #CipherSafeApp QMenu {{ background-color: #2D2D30; color: #F1F1F1; border: 1px solid #555; }}
            #CipherSafeApp QMenu::item:selected {{ background-color: #0078D4; }}
            #CipherSafeApp #EncryptButton, #CipherSafeApp #DecryptButton, #BatchRenameApp #EncryptButton, #TextCryptoDialog #EncryptButton, #TextCryptoDialog #DecryptButton {{ color: white; font-weight: bold; font-size: 12pt; border: none; background-color: #0078D4; }}
            #CipherSafeApp #DecryptButton, #TextCryptoDialog #DecryptButton {{ background-color: #C50F1F; }}
            #CipherSafeApp #EncryptButton:hover, #BatchRenameApp #EncryptButton:hover, #TextCryptoDialog #EncryptButton:hover {{ background-color: #1088E4; }}
            #CipherSafeApp #DecryptButton:hover, #TextCryptoDialog #DecryptButton:hover {{ background-color: #D51F2F; }}
            #CipherSafeApp QProgressBar, #BatchRenameApp QProgressBar {{ border: 1px solid rgba(255, 255, 255, 0.2); background-color: rgba(0, 0, 0, 0.3); border-radius: 3px; text-align: center; color: white; }}
            #CipherSafeApp QProgressBar::chunk, #BatchRenameApp QProgressBar::chunk {{ background-color: #0078D4; border-radius: 2px; }}
            #CipherSafeApp QCheckBox#OptionCheckbox, #TextCryptoDialog QCheckBox, #TextCryptoDialog QRadioButton {{ color: #CCCCCC; margin-left: 10px; }}
            #CipherSafeApp QCheckBox#OptionCheckbox::indicator, #TextCryptoDialog QCheckBox::indicator {{ width: 15px; height: 15px; border: 1px solid #AAAAAA; border-radius: 3px; }}
            #CipherSafeApp QCheckBox#OptionCheckbox::indicator:checked, #TextCryptoDialog QCheckBox::indicator:checked {{ background-color: #0078D4; border-color: #0078D4; }}
            #CipherSafeApp #ToolsLabel {{ color: #CCCCCC; font-weight: bold; }}
            #CipherSafeApp #Separator {{ background-color: rgba(255, 255, 255, 0.2); }}
            #CipherSafeApp QPushButton#AboutButton {{ background-color: transparent; border: 1px solid rgba(255, 255, 255, 0.4); font-size: 9pt; color: #CCCCCC; }}
            #CipherSafeApp QPushButton#AboutButton:hover {{ background-color: rgba(255, 255, 255, 0.1); border-color: rgba(255, 255, 255, 0.7); }}
            #TextCryptoDialog, #BatchRenameApp, ReportDialog {{ background-color: {text_crypto_dialog_bg}; }}
            QTextEdit, QLineEdit {{ background-color: rgba(0, 0, 0, 0.2); border: 1px solid rgba(255, 255, 255, 0.3); color: white; padding: 5px; border-radius: 3px; }}
            QScrollArea#ReportScrollArea {{ background-color: rgba(0, 0, 0, 0.2); border: 1px solid #444; }}
            QScrollArea#ReportScrollArea > QWidget > QWidget {{ background-color: transparent; }}
        """

    def paintEvent(self, event):
        if self.background_pixmap:
            painter = QPainter(self)
            scaled_pixmap = self.background_pixmap.scaled(self.size(), Qt.AspectRatioMode.KeepAspectRatioByExpanding, Qt.TransformationMode.SmoothTransformation)
            x = (self.width() - scaled_pixmap.width()) / 2; y = (self.height() - scaled_pixmap.height()) / 2
            painter.drawPixmap(int(x), int(y), scaled_pixmap)
        super().paintEvent(event)

    def resizeEvent(self, event): self.update(); super().resizeEvent(event)

    def get_current_drop_label(self): return self.password_mode_file_drop_label if self.current_mode == 'password' else self.keyfile_mode_file_drop_label

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            if not self._is_dragging:
                self._is_dragging = True
                self.get_current_drop_label().setStyleSheet("#CipherSafeApp #DropLabel { border-color: #0078D4; background-color: rgba(0, 120, 212, 0.2); color: white; }")

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dragLeaveEvent(self, event):
        if self._is_dragging:
            self._is_dragging = False
            self.get_current_drop_label().setStyleSheet("")

    def dropEvent(self, event):
        if self._is_dragging:
            self._is_dragging = False
            self.get_current_drop_label().setStyleSheet("")
        
        if event.mimeData().hasUrls():
            path = event.mimeData().urls()[0].toLocalFile()
            if path.lower().endswith('.key') and self.current_mode == 'keyfile':
                self.update_key_file_path(path)
            else:
                self.update_input_path(path)

    def update_input_path(self, path):
        self.input_path = path; is_dir = os.path.isdir(path) if path else False; name = os.path.basename(path) if path else ""
        text = f"<b>已選{'資料夾' if is_dir else '檔案'}:</b><br>{name}" if path else "將檔案或資料夾拖曳至此"
        self.get_current_drop_label().setText(text)
        self.save_to_original_path_checkbox.setEnabled(bool(path))

    def update_key_file_path(self, path): self.key_file_path = path; self.select_key_btn.setText(f"已選: {os.path.basename(path)}" if path else "選擇金鑰檔案...")

    def select_file(self): fname, _ = QFileDialog.getOpenFileName(self, '選擇檔案', '', '所有檔案 (*.*)'); self.update_input_path(fname) if fname else None

    def select_folder(self): dname = QFileDialog.getExistingDirectory(self, '選擇資料夾'); self.update_input_path(dname) if dname else None

    def select_key_file(self): fname, _ = QFileDialog.getOpenFileName(self, '選擇金鑰檔案', '', '金鑰檔案 (*.key)'); self.update_key_file_path(fname) if fname else None

    def _confirm_overwrite(self, fname: str) -> bool:
        reply = QMessageBox.critical(self, 
                                     "警告：即將覆寫檔案",
                                     f"您將要覆寫一個已存在的金鑰檔案：\n{os.path.basename(fname)}\n\n"
                                     "此操作是毀滅性的，將導致使用該舊金鑰加密的所有資料永久無法復原！"
                                     "您確定要繼續嗎？",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                                     QMessageBox.StandardButton.Cancel)
        return reply == QMessageBox.StandardButton.Yes

    def generate_key_unencrypted(self):
        fname, _ = QFileDialog.getSaveFileName(self, '儲存新的金鑰檔案', '', '金鑰檔案 (*.key)')
        if fname:
            if not fname.endswith('.key'): fname += '.key'
            if os.path.exists(fname) and not self._confirm_overwrite(fname): return
            success, message = CryptoLogic.create_key_file(fname)
            if success: self.update_key_file_path(fname)
            QMessageBox.information(self, "產生結果", message)

    def generate_key_encrypted(self):
        level_dialog = SecurityLevelDialog(self)
        if level_dialog.exec() == QDialog.DialogCode.Accepted:
            level = level_dialog.get_level(); pass_dialog = SimplePasswordDialog(self, "請輸入一個新密碼來保護金鑰：")
            if pass_dialog.exec() == QDialog.DialogCode.Accepted:
                password = pass_dialog.get_password()
                if not password: QMessageBox.warning(self, "密碼為空", "密碼不能為空。"); return
                fname, _ = QFileDialog.getSaveFileName(self, '儲存新的帶密碼的金鑰', '', '金鑰檔案 (*.key)')
                if fname:
                    if not fname.endswith('.key'): fname += '.key'
                    if os.path.exists(fname) and not self._confirm_overwrite(fname): return
                    success, message = CryptoLogic.create_key_file(fname, password=password, level=level)
                    if success: self.update_key_file_path(fname)
                    QMessageBox.information(self, "產生結果", message)

    def generate_key_recoverable(self):
        level_dialog = SecurityLevelDialog(self)
        if level_dialog.exec() == QDialog.DialogCode.Accepted:
            level = level_dialog.get_level(); pass_dialog = SimplePasswordDialog(self, "首先，請輸入一個主密碼：")
            if pass_dialog.exec() == QDialog.DialogCode.Accepted:
                password = pass_dialog.get_password()
                if not password: QMessageBox.warning(self, "密碼為空", "主密碼不能為空。"); return
                rec_dialog = SetupRecoveryDialog(self)
                if rec_dialog.exec() == QDialog.DialogCode.Accepted:
                    recovery_data = rec_dialog.get_recovery_data()
                    if not recovery_data: QMessageBox.warning(self, "輸入不完整", "問題和答案均不能為空。"); return
                    fname, _ = QFileDialog.getSaveFileName(self, '儲存帶復原功能的金鑰', '', '金鑰檔案 (*.key)')
                    if fname:
                        if not fname.endswith('.key'): fname += '.key'
                        if os.path.exists(fname) and not self._confirm_overwrite(fname): return
                        success, message = CryptoLogic.create_key_file(fname, password=password, recovery_data=recovery_data, level=level)
                        if success: self.update_key_file_path(fname)
                        QMessageBox.information(self, "產生結果", message)

    def cancel_operation(self):
        if self.worker:
            logging.info("使用者點擊了中斷按鈕。")
            self.worker.stop()
            self.cancel_button.setText("正在中斷...")
            self.cancel_button.setEnabled(False)

    def update_progress(self, current, total, filename):
        self.progress_bar.setRange(0, total); self.progress_bar.setValue(current); self.progress_bar.setFormat(f"正在處理: {current}/{total} - {filename}")

    def open_folder(self, path):
        try:
            logging.info(f"嘗試開啟輸出目錄: {path}")
            if sys.platform == 'win32': os.startfile(os.path.realpath(path))
            elif sys.platform == 'darwin': subprocess.run(['open', path])
            else: subprocess.run(['xdg-open', path])
        except Exception as e:
            logging.error(f"開啟目錄失敗: {e}", exc_info=True)
            QMessageBox.warning(self, "開啟失敗", f"無法開啟目錄：{e}")

    def set_ui_enabled(self, enabled: bool):
        self.progress_bar.setVisible(not enabled)
        self.cancel_button.setVisible(not enabled)
        if enabled:
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(0)
            self.cancel_button.setText("中斷操作")
            self.cancel_button.setEnabled(True)
        
        for widget in self._managed_buttons:
            widget.setEnabled(enabled)
        
        self.delete_source_checkbox.setEnabled(enabled)
        self.save_to_original_path_checkbox.setEnabled(enabled)
        if enabled:
            self.update_input_path(self.input_path)

if __name__ == '__main__':
    # --- 日誌和異常處理設定 ---
    log_file_path = setup_logging()
    sys.log_file_path = log_file_path # 將路徑存入sys，方便異常鉤子獲取
    sys.excepthook = handle_exception
    logging.info("=================================================")
    logging.info("CipherSafe 應用程式啟動")
    logging.info(f"平台: {sys.platform}, Python 版本: {sys.version.split()[0]}")
    # ---

    app = QApplication(sys.argv)
    app.setStyleSheet("""
        QDialog, QMessageBox { background-color: #2D2D30; color: #F1F1F1; font-family: "Segoe UI", "Microsoft YaHei", sans-serif; }
        QDialog QLabel, QMessageBox QLabel { color: #CCCCCC; }
        QDialog QLineEdit, QDialog QTextEdit, QDialog QComboBox { background-color: #3D3D40; border: 1px solid #555; color: white; padding: 5px; border-radius: 3px; }
        QDialog QComboBox::drop-down { border: none; }
        QDialog QComboBox::down-arrow { image: url(none); }
        QDialog QComboBox QAbstractItemView { background-color: #3D3D40; selection-background-color: #0078D4; border: 1px solid #555; }
        QDialog QCheckBox, QDialog QRadioButton { color: #AAAAAA; }
        QDialogButtonBox QPushButton, QMessageBox QPushButton { background-color: #0078D4; color: white; border: none; padding: 8px 20px; font-size: 10pt; border-radius: 5px; min-width: 80px; }
        QDialogButtonBox QPushButton:hover, QMessageBox QPushButton:hover { background-color: #1088E4; }
        #DropLabel { background-color: rgba(0, 0, 0, 0.2); border: 1px dashed rgba(255, 255, 255, 0.3); border-radius: 8px; min-height: 80px; font-size: 11pt; color: #AAAAAA; }
        #EncryptButton { background-color: #0078D4; color: white; font-weight: bold; font-size: 12pt; border: none; }
        #EncryptButton:hover { background-color: #1088E4; }
        QScrollArea#ReportScrollArea { background-color: rgba(0, 0, 0, 0.2); border: 1px solid #444; }
        QScrollArea#ReportScrollArea > QWidget > QWidget { background-color: transparent; }
    """)
    
    try:
        window = CipherSafeApp()
        window.show()
        logging.info("主視窗已成功建立並顯示")
        exit_code = app.exec()
        logging.info(f"應用程式正常退出，退出碼: {exit_code}")
        sys.exit(exit_code)
    except Exception as e:
        # 捕獲在初始化期間可能發生的任何異常
        logging.critical(f"在應用程式初始化或主迴圈中發生致命錯誤。", exc_info=True)
        # excepthook 會自動呼叫 handle_exception
        sys.exit(1)
