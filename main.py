import slint
from rsaa import RSA_plain
import base64
import os
from datetime import timedelta


# slint.loader will look in `sys.path` for `app-window.slint`.
class App(slint.loader.app_window.AppWindow):
    def __init__(self):
        super().__init__()
        self.rsa = RSA_plain()
        self.app_dir = os.path.dirname(os.path.abspath(__file__))
        # 实时预览轮询相关
        self._last_plaintext = ""
        self.preview_status = ""
        # 启动轮询 Timer (500ms间隔)
        self._preview_timer = slint.Timer()
        self._preview_timer.start(slint.TimerMode.Repeated, timedelta(seconds=0.5), lambda: self._poll_preview())

    @slint.callback
    def generate_keys(self):
        try:
            self.rsa.generate_keys()
            self.has_keys = True
            self.status = "Keys generated"
        except Exception as e:
            self.status = f"Generation failed: {str(e)}"

    @slint.callback
    def encrypt_text(self, plaintext):
        try:
            ciphertext = self.rsa.encrypt(plaintext.encode("utf-8"))
            self.ciphertext = base64.b64encode(ciphertext).decode("ascii")
            self.current_ciphertext = ciphertext  # Save raw bytes
            self.status = "Encryption successful"
        except Exception as e:
            self.status = f"Encryption failed: {str(e)}"

    @slint.callback
    def decrypt_text(self, ciphertext_b64):
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            plaintext = self.rsa.decrypt(ciphertext).decode("utf-8")
            self.plaintext = plaintext
            self.status = "Decryption successful"
        except Exception as e:
            self.status = f"Decryption failed: {str(e)}"

    @slint.callback
    def save_ciphertext_bin(self):
        """Save ciphertext as binary file, filename uses first 10 chars of Hex"""
        try:
            if not hasattr(self, 'current_ciphertext') or self.current_ciphertext is None:
                self.status = "No ciphertext to save"
                return
            ciphertext_dir = os.path.join(self.app_dir, "ciphertexts")
            os.makedirs(ciphertext_dir, exist_ok=True)
            filename = RSA_plain.save_ciphertext(self.current_ciphertext, ciphertext_dir)
            self.status = f"Ciphertext saved: {filename}"
        except Exception as e:
            self.status = f"Save failed: {str(e)}"

    @slint.callback
    def save_keys(self):
        try:
            private_path = os.path.join(self.app_dir, "private_key.pem")
            public_path = os.path.join(self.app_dir, "public_key.pem")
            self.rsa.save_private_key(private_path)
            self.rsa.save_public_key(public_path)
            self.status = "Keys saved to file"
        except Exception as e:
            self.status = f"Save failed: {str(e)}"

    @slint.callback
    def load_keys(self):
        try:
            private_path = os.path.join(self.app_dir, "private_key.pem")
            self.rsa.load_private_key(private_path)
            self.has_keys = True
            self.status = "Keys loaded from file"
        except FileNotFoundError:
            try:
                public_path = os.path.join(self.app_dir, "public_key.pem")
                self.rsa.load_public_key(public_path)
                self.has_keys = True
                self.status = "Public key loaded (encryption only)"
            except FileNotFoundError:
                self.status = "Key files not found"
        except Exception as e:
            self.status = f"Load failed: {str(e)}"

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
            self.status = f"Loaded: {filename}"
        except Exception as e:
            self.status = f"Load failed: {str(e)}"

    def _poll_preview(self):
        """轮询检测文本变化，触发预览加密"""
        current_text = self.plaintext
        # 只有文本真正变化时才加密
        if current_text != self._last_plaintext:
            self._last_plaintext = current_text
            self._do_preview(current_text)

    def _do_preview(self, text: str):
        """实际执行预览加密"""
        if not self.has_keys:
            if text:  # 只有输入了文本才显示错误
                self.preview_status = "错误：无密钥，请先生成或加载密钥"
            else:
                self.preview_status = ""
            return

        if not text:
            self.preview_status = ""
            return

        try:
            ciphertext = self.rsa.encrypt(text.encode("utf-8"))
            self.ciphertext = base64.b64encode(ciphertext).decode("ascii")
            self.preview_status = "✓ 预览已更新"
        except Exception as e:
            self.preview_status = f"加密错误：{str(e)}"


if __name__ == "__main__":
    app = App()
    app.run()
