import slint
from rsaa import RSA_plain
import base64
import os
from datetime import timedelta
import tkinter as tk
from tkinter import filedialog, messagebox


# slint.loader will look in `sys.path` for `app-window.slint`.
class App(slint.loader.app_window.AppWindow):
    def __init__(self):
        super().__init__()
        self.rsa = RSA_plain()
        self.app_dir = os.path.dirname(os.path.abspath(__file__))
        # 实时预览轮询相关
        self._last_plaintext = ""
        self.preview_status = ""
        # 隐藏 tkinter 窗口（用于文件对话框）
        self._tk_root = tk.Tk()
        self._tk_root.withdraw()
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
        # 只有启用预览时才执行
        if not self.preview_enabled:
            return

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

    # ==================== 文件操作回调 ====================

    @slint.callback
    def select_source_file(self):
        """选择源文件"""
        filepath = filedialog.askopenfilename(
            title="Select file to encrypt",
            parent=self._tk_root,
        )
        if filepath:
            self.selected_file = filepath
            # 显示文件信息
            size = os.path.getsize(filepath)
            if size < 1024:
                size_str = f"{size} B"
            elif size < 1024 * 1024:
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = f"{size / (1024 * 1024):.1f} MB"
            self.file_info = f"📄 {os.path.basename(filepath)} ({size_str})"
            self.file_status = ""
            self.progress_value = 0

    @slint.callback
    def select_cipher_file(self):
        """选择密文文件"""
        rsa_dir = os.path.join(self.app_dir, "ciphertexts")
        filepath = filedialog.askopenfilename(
            title="Select encrypted file",
            parent=self._tk_root,
            initialdir=rsa_dir,
            filetypes=[("RSA encrypted files", "*.rsa"), ("All files", "*.*")],
        )
        if filepath:
            self.selected_cipher = filepath
            self.file_status = ""

    @slint.callback
    def get_rsa_file_list(self):
        """获取 .rsa 文件列表"""
        rsa_dir = os.path.join(self.app_dir, "ciphertexts")
        if not os.path.exists(rsa_dir):
            os.makedirs(rsa_dir, exist_ok=True)
        files = [f for f in os.listdir(rsa_dir) if f.endswith(".rsa")]
        self.rsa_file_items = slint.ListModel([{"text": f} for f in files])

    def _progress_callback(self, processed: int, total: int):
        """进度回调"""
        if total > 0:
            self.progress_value = processed / total
            if processed < total:
                percent = (processed * 100) // total
                self.file_progress = f"Processing: {percent}% ({processed}/{total} bytes)"
            else:
                self.file_progress = "Complete!"

    @slint.callback
    def encrypt_file(self):
        """加密文件"""
        if not self.selected_file:
            self.file_status = "请先选择文件"
            return

        try:
            # 生成输出文件名
            ciphertext_dir = os.path.join(self.app_dir, "ciphertexts")
            os.makedirs(ciphertext_dir, exist_ok=True)

            # 先加密获取文件名
            with open(self.selected_file, "rb") as f:
                sample = f.read(10)
            dst_filename = RSA_plain.get_ciphertext_filename(sample) + ".rsa"
            dst_path = os.path.join(ciphertext_dir, dst_filename)

            # 执行加密
            self.progress_value = 0
            self.file_status = "加密中..."
            result = self.rsa.encrypt_file(self.selected_file, dst_path,
                                           self._progress_callback)

            # 计算膨胀率
            src_size = os.path.getsize(self.selected_file)
            dst_size = os.path.getsize(dst_path)
            ratio = dst_size / src_size if src_size > 0 else 0

            self.file_status = f"✓ 完成！输出: {dst_filename}"
            self.progress_value = 1
            self.file_progress = f"膨胀率: {ratio:.2f}x ({src_size} → {dst_size} bytes)"

            # 刷新文件列表
            self.get_rsa_file_list()

        except Exception as e:
            self.file_status = f"✗ 加密失败: {str(e)}"
            self.progress_value = 0

    @slint.callback
    def decrypt_file(self):
        """解密文件"""
        if not self.selected_cipher:
            self.file_status = "请先选择加密文件"
            return

        try:
            # 验证文件格式
            metadata = RSA_plain.validate_rsaf_file(self.selected_cipher)
            if metadata is None:
                self.file_status = "✗ 无效的 RSAF 文件格式"
                return

            # 生成输出路径（使用原始文件名）
            output_dir = os.path.join(self.app_dir, "decrypted")
            os.makedirs(output_dir, exist_ok=True)
            dst_path = os.path.join(output_dir, metadata["filename"])

            # 检查文件是否已存在
            if os.path.exists(dst_path):
                if not messagebox.askyesno("File exists", f"Overwrite {dst_path}?"):
                    self.file_status = "已取消"
                    return

            # 执行解密
            self.progress_value = 0
            self.file_status = "解密中..."
            result = self.rsa.decrypt_file(self.selected_cipher, dst_path,
                                           self._progress_callback)

            self.file_status = f"✓ 完成！保存为: {result['filename']}"
            self.progress_value = 1
            self.file_progress = f"文件大小: {result['size']} bytes"

        except Exception as e:
            self.file_status = f"✗ 解密失败: {str(e)}"
            self.progress_value = 0


if __name__ == "__main__":
    app = App()
    app.run()
