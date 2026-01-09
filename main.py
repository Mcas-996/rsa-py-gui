import slint
from rsaa import RSA_plain
import base64
import os
from datetime import timedelta
import tkinter as tk
from tkinter import filedialog, messagebox


# Localized strings
STRINGS = {
    0: {  # English
        "keys-generated": "Keys generated",
        "gen-failed": "Generation failed: ",
        "enc-success": "Encryption successful",
        "enc-failed": "Encryption failed: ",
        "dec-success": "Decryption successful",
        "dec-failed": "Decryption failed: ",
        "no-ciphertext": "No ciphertext to save",
        "cipher-saved": "Ciphertext saved: ",
        "save-failed": "Save failed: ",
        "keys-saved": "Keys saved to file",
        "keys-loaded": "Keys loaded from file",
        "pub-loaded": "Public key loaded (encryption only)",
        "no-keys": "Key files not found",
        "load-failed": "Load failed: ",
        "loaded": "Loaded: ",
        "preview-no-keys": "Error: No keys. Generate or load keys first",
        "preview-ok": "OK Preview updated",
        "preview-err": "Encrypt error: ",
        "select-file": "Select file to encrypt",
        "file-info": " {} ({})",
        "select-cipher": "Select encrypted file",
        "select-file-first": "Please select a file first",
        "encrypting": "Encrypting...",
        "ok-output": "OK Output: ",
        "expansion": "Expansion: {:.2f}x ({} -> {} bytes)",
        "fail-enc": "FAIL Encrypt failed: ",
        "select-cipher-first": "Please select an encrypted file first",
        "invalid-format": "FAIL Invalid RSAF file format",
        "overwrite": "Overwrite ",
        "cancelled": "Cancelled",
        "decrypting": "Decrypting...",
        "ok-saved": "OK Saved: ",
        "file-size": "File size: {} bytes",
        "fail-dec": "FAIL Decrypt failed: ",
    },
    1: {  # Chinese
        "keys-generated": "密钥已生成",
        "gen-failed": "生成失败: ",
        "enc-success": "加密成功",
        "enc-failed": "加密失败: ",
        "dec-success": "解密成功",
        "dec-failed": "解密失败: ",
        "no-ciphertext": "没有密文可保存",
        "cipher-saved": "密文已保存: ",
        "save-failed": "保存失败: ",
        "keys-saved": "密钥已保存",
        "keys-loaded": "密钥已加载",
        "pub-loaded": "公钥已加载（仅可加密）",
        "no-keys": "未找到密钥文件",
        "load-failed": "加载失败: ",
        "loaded": "已加载: ",
        "preview-no-keys": "错误：无密钥，请先生成或加载密钥",
        "preview-ok": "✓ 预览已更新",
        "preview-err": "加密错误: ",
        "select-file": "选择要加密的文件",
        "file-info": " {} ({})",
        "select-cipher": "选择加密文件",
        "select-file-first": "请先选择文件",
        "encrypting": "加密中...",
        "ok-output": "✓ 输出: ",
        "expansion": "膨胀率: {:.2f}x ({} -> {} 字节)",
        "fail-enc": "✗ 加密失败: ",
        "select-cipher-first": "请先选择加密文件",
        "invalid-format": "✗ 无效的 RSAF 文件格式",
        "overwrite": "覆盖 ",
        "cancelled": "已取消",
        "decrypting": "解密中...",
        "ok-saved": "✓ 已保存: ",
        "file-size": "文件大小: {} 字节",
        "fail-dec": "✗ 解密失败: ",
    },
}


# slint.loader will look in `sys.path` for `app-window.slint`.
class App(slint.loader.app_window.AppWindow):
    def __init__(self):
        super().__init__()
        self.rsa = RSA_plain()
        self.app_dir = os.path.dirname(os.path.abspath(__file__))
        # Real-time preview polling
        self._last_plaintext = ""
        self.preview_status = ""
        self.language = 0  # 0=English, 1=Chinese
        # Hide tkinter window for file dialogs
        self._tk_root = tk.Tk()
        self._tk_root.withdraw()
        # Start polling timer (500ms interval)
        self._preview_timer = slint.Timer()
        self._preview_timer.start(slint.TimerMode.Repeated, timedelta(seconds=0.5), lambda: self._poll_preview())

    def _(self, key: str) -> str:
        """Get localized string"""
        return STRINGS[self.language].get(key, key)

    @slint.callback
    def generate_keys(self):
        try:
            self.rsa.generate_keys()
            self.has_keys = True
            self.status = self._("keys-generated")
        except Exception as e:
            self.status = self._("gen-failed") + str(e)

    @slint.callback
    def encrypt_text(self, plaintext):
        try:
            ciphertext = self.rsa.encrypt(plaintext.encode("utf-8"))
            self.ciphertext = base64.b64encode(ciphertext).decode("ascii")
            self.current_ciphertext = ciphertext  # Save raw bytes
            self.status = self._("enc-success")
        except Exception as e:
            self.status = self._("enc-failed") + str(e)

    @slint.callback
    def decrypt_text(self, ciphertext_b64):
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            plaintext = self.rsa.decrypt(ciphertext).decode("utf-8")
            self.plaintext = plaintext
            self.status = self._("dec-success")
        except Exception as e:
            self.status = self._("dec-failed") + str(e)

    @slint.callback
    def save_ciphertext_bin(self):
        """Save ciphertext as binary file, filename uses first 10 chars of Hex"""
        try:
            if not hasattr(self, 'current_ciphertext') or self.current_ciphertext is None:
                self.status = self._("no-ciphertext")
                return
            ciphertext_dir = os.path.join(self.app_dir, "ciphertexts")
            os.makedirs(ciphertext_dir, exist_ok=True)
            filename = RSA_plain.save_ciphertext(self.current_ciphertext, ciphertext_dir)
            self.status = self._("cipher-saved") + filename
        except Exception as e:
            self.status = self._("save-failed") + str(e)

    @slint.callback
    def save_keys(self):
        try:
            private_path = os.path.join(self.app_dir, "private_key.pem")
            public_path = os.path.join(self.app_dir, "public_key.pem")
            self.rsa.save_private_key(private_path)
            self.rsa.save_public_key(public_path)
            self.status = self._("keys-saved")
        except Exception as e:
            self.status = self._("save-failed") + str(e)

    @slint.callback
    def load_keys(self):
        try:
            private_path = os.path.join(self.app_dir, "private_key.pem")
            self.rsa.load_private_key(private_path)
            self.has_keys = True
            self.status = self._("keys-loaded")
        except FileNotFoundError:
            try:
                public_path = os.path.join(self.app_dir, "public_key.pem")
                self.rsa.load_public_key(public_path)
                self.has_keys = True
                self.status = self._("pub-loaded")
            except FileNotFoundError:
                self.status = self._("no-keys")
        except Exception as e:
            self.status = self._("load-failed") + str(e)

    @slint.callback
    def get_ciphertext_list(self):
        """Get ciphertext file list"""
        ciphertext_dir = os.path.join(self.app_dir, "ciphertexts")
        files = RSA_plain.list_ciphertext_files(ciphertext_dir)
        # Use Slint ListModel
        self.ciphertext_items = slint.ListModel([{"text": f} for f in files])

    @slint.callback
    def load_ciphertext_file(self, filename: str):
        """Load ciphertext file"""
        try:
            filepath = os.path.join(self.app_dir, "ciphertexts", filename)
            ciphertext = RSA_plain.load_ciphertext(filepath)
            self.ciphertext = base64.b64encode(ciphertext).decode("ascii")
            self.current_ciphertext = ciphertext
            self.status = self._("loaded") + filename
        except Exception as e:
            self.status = self._("load-failed") + str(e)

    def _poll_preview(self):
        """Poll for text changes and trigger preview encryption"""
        if not self.preview_enabled:
            return

        current_text = self.plaintext
        if current_text != self._last_plaintext:
            self._last_plaintext = current_text
            self._do_preview(current_text)

    def _do_preview(self, text: str):
        """Perform preview encryption"""
        if not self.has_keys:
            if text:
                self.preview_status = self._("preview-no-keys")
            else:
                self.preview_status = ""
            return

        if not text:
            self.preview_status = ""
            return

        try:
            ciphertext = self.rsa.encrypt(text.encode("utf-8"))
            self.ciphertext = base64.b64encode(ciphertext).decode("ascii")
            self.preview_status = self._("preview-ok")
        except Exception as e:
            self.preview_status = self._("preview-err") + str(e)

    # ==================== File callbacks ====================

    @slint.callback
    def select_source_file(self):
        """Select source file to encrypt"""
        filepath = filedialog.askopenfilename(
            title=self._("select-file"),
            parent=self._tk_root,
        )
        if filepath:
            self.selected_file = filepath
            size = os.path.getsize(filepath)
            if size < 1024:
                size_str = f"{size} B"
            elif size < 1024 * 1024:
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = f"{size / (1024 * 1024):.1f} MB"
            self.file_info = self._("file-info").format(os.path.basename(filepath), size_str)
            self.file_status = ""
            self.progress_value = 0

    @slint.callback
    def select_cipher_file(self):
        """Select encrypted file to decrypt"""
        rsa_dir = os.path.join(self.app_dir, "ciphertexts")
        filepath = filedialog.askopenfilename(
            title=self._("select-cipher"),
            parent=self._tk_root,
            initialdir=rsa_dir,
            filetypes=[("RSA encrypted files", "*.rsa"), ("All files", "*.*")],
        )
        if filepath:
            self.selected_cipher = filepath
            self.file_status = ""

    @slint.callback
    def get_rsa_file_list(self):
        """Get .rsa file list"""
        rsa_dir = os.path.join(self.app_dir, "ciphertexts")
        if not os.path.exists(rsa_dir):
            os.makedirs(rsa_dir, exist_ok=True)
        files = [f for f in os.listdir(rsa_dir) if f.endswith(".rsa")]
        self.rsa_file_items = slint.ListModel([{"text": f} for f in files])

    def _progress_callback(self, processed: int, total: int):
        """Progress callback"""
        if total > 0:
            self.progress_value = processed / total
            if processed < total:
                percent = (processed * 100) // total
                self.file_progress = f"Processing: {percent}% ({processed}/{total} bytes)"
            else:
                self.file_progress = "Complete!"

    @slint.callback
    def encrypt_file(self):
        """Encrypt file"""
        if not self.selected_file:
            self.file_status = self._("select-file-first")
            return

        try:
            ciphertext_dir = os.path.join(self.app_dir, "ciphertexts")
            os.makedirs(ciphertext_dir, exist_ok=True)

            with open(self.selected_file, "rb") as f:
                sample = f.read(10)
            dst_filename = RSA_plain.get_ciphertext_filename(sample) + ".rsa"
            dst_path = os.path.join(ciphertext_dir, dst_filename)

            self.progress_value = 0
            self.file_status = self._("encrypting")
            result = self.rsa.encrypt_file(self.selected_file, dst_path,
                                           self._progress_callback)

            src_size = os.path.getsize(self.selected_file)
            dst_size = os.path.getsize(dst_path)
            ratio = dst_size / src_size if src_size > 0 else 0

            self.file_status = self._("ok-output") + dst_filename
            self.progress_value = 1
            self.file_progress = self._("expansion").format(ratio, src_size, dst_size)

            self.get_rsa_file_list()

        except Exception as e:
            self.file_status = self._("fail-enc") + str(e)
            self.progress_value = 0

    @slint.callback
    def decrypt_file(self):
        """Decrypt file"""
        if not self.selected_cipher:
            self.file_status = self._("select-cipher-first")
            return

        try:
            metadata = RSA_plain.validate_rsaf_file(self.selected_cipher)
            if metadata is None:
                self.file_status = self._("invalid-format")
                return

            output_dir = os.path.join(self.app_dir, "decrypted")
            os.makedirs(output_dir, exist_ok=True)
            dst_path = os.path.join(output_dir, metadata["filename"])

            if os.path.exists(dst_path):
                if not messagebox.askyesno("File exists", self._("overwrite") + dst_path + "?"):
                    self.file_status = self._("cancelled")
                    return

            self.progress_value = 0
            self.file_status = self._("decrypting")
            result = self.rsa.decrypt_file(self.selected_cipher, dst_path,
                                           self._progress_callback)

            self.file_status = self._("ok-saved") + result["filename"]
            self.progress_value = 1
            self.file_progress = self._("file-size").format(result["size"])

        except Exception as e:
            self.file_status = self._("fail-dec") + str(e)
            self.progress_value = 0

    # ==================== Settings callbacks ====================

    @slint.callback
    def set_language(self, index: int):
        """Set language (0=English, 1=Chinese)"""
        self.language = index


if __name__ == "__main__":
    app = App()
    app.run()
