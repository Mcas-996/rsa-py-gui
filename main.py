import slint
from rsaa import RSA_plain
import base64
import os


# slint.loader will look in `sys.path` for `app-window.slint`.
class App(slint.loader.app_window.AppWindow):
    def __init__(self):
        super().__init__()
        self.rsa = RSA_plain()
        self.app_dir = os.path.dirname(os.path.abspath(__file__))

    @slint.callback
    def generate_keys(self):
        try:
            self.rsa.generate_keys()
            self.has_keys = True
            self.status = "密钥已生成"
        except Exception as e:
            self.status = f"生成失败: {str(e)}"

    @slint.callback
    def encrypt_text(self, plaintext):
        try:
            ciphertext = self.rsa.encrypt(plaintext.encode("utf-8"))
            self.ciphertext = base64.b64encode(ciphertext).decode("ascii")
            self.current_ciphertext = ciphertext  # 保存原始 bytes
            self.status = "加密成功"
        except Exception as e:
            self.status = f"加密失败: {str(e)}"

    @slint.callback
    def decrypt_text(self, ciphertext_b64):
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            plaintext = self.rsa.decrypt(ciphertext).decode("utf-8")
            self.plaintext = plaintext
            self.status = "解密成功"
        except Exception as e:
            self.status = f"解密失败: {str(e)}"

    @slint.callback
    def save_ciphertext_bin(self):
        """将密文保存为二进制文件，文件名用 Hex 前20位"""
        try:
            if not hasattr(self, 'current_ciphertext') or self.current_ciphertext is None:
                self.status = "无密文可保存"
                return
            ciphertext_dir = os.path.join(self.app_dir, "ciphertexts")
            os.makedirs(ciphertext_dir, exist_ok=True)
            filename = RSA_plain.save_ciphertext(self.current_ciphertext, ciphertext_dir)
            self.status = f"密文已保存: {filename}"
        except Exception as e:
            self.status = f"保存失败: {str(e)}"

    @slint.callback
    def save_keys(self):
        try:
            private_path = os.path.join(self.app_dir, "private_key.pem")
            public_path = os.path.join(self.app_dir, "public_key.pem")
            self.rsa.save_private_key(private_path)
            self.rsa.save_public_key(public_path)
            self.status = "密钥已保存到文件"
        except Exception as e:
            self.status = f"保存失败: {str(e)}"

    @slint.callback
    def load_keys(self):
        try:
            private_path = os.path.join(self.app_dir, "private_key.pem")
            self.rsa.load_private_key(private_path)
            self.has_keys = True
            self.status = "密钥已从文件加载"
        except FileNotFoundError:
            try:
                public_path = os.path.join(self.app_dir, "public_key.pem")
                self.rsa.load_public_key(public_path)
                self.has_keys = True
                self.status = "公钥已加载 (仅加密模式)"
            except FileNotFoundError:
                self.status = "未找到密钥文件"
        except Exception as e:
            self.status = f"加载失败: {str(e)}"

    @slint.callback
    def get_ciphertext_list(self):
        """获取密文文件列表"""
        ciphertext_dir = os.path.join(self.app_dir, "ciphertexts")
        files = RSA_plain.list_ciphertext_files(ciphertext_dir)
        # 使用 Slint ListModel
        self.ciphertext_items = slint.ListModel([{"text": f} for f in files])

    @slint.callback
    def load_ciphertext_file(self, filename: str):
        """加载密文文件"""
        try:
            filepath = os.path.join(self.app_dir, "ciphertexts", filename)
            ciphertext = RSA_plain.load_ciphertext(filepath)
            self.ciphertext = base64.b64encode(ciphertext).decode("ascii")
            self.current_ciphertext = ciphertext
            self.status = f"已加载: {filename}"
        except Exception as e:
            self.status = f"加载失败: {str(e)}"


if __name__ == "__main__":
    app = App()
    app.run()