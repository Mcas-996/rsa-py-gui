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


if __name__ == "__main__":
    app = App()
    app.run()