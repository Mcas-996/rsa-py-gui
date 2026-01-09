from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
import os


class RSA_plain:
    def __init__(self):
        self._private_key = None
        self._public_key = None

    @property
    def private_key(self):
        if self._private_key is None:
            raise ValueError("Keys not generated. Call generate_keys() first.")
        return self._private_key

    @property
    def public_key(self):
        if self._public_key is None:
            raise ValueError("Keys not generated. Call generate_keys() first.")
        return self._public_key

    def generate_keys(self):
        self._private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self._public_key = self._private_key.public_key()

    def encrypt(self, plaintext: bytes) -> bytes:
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
        if self._public_key is None:
            raise ValueError("Keys not generated. Call generate_keys() first.")
        return self.public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def decrypt(self, ciphertext: bytes) -> bytes:
        if not isinstance(ciphertext, bytes):
            raise TypeError("ciphertext must be bytes")
        if self._private_key is None:
            raise ValueError("Keys not generated. Call generate_keys() first.")
        return self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def save_private_key(self, path: str, password: bytes | None = None):
        """保存私钥到文件"""
        if self._private_key is None:
            raise ValueError("Keys not generated. Call generate_keys() first.")
        encryption = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        with open(path, "wb") as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption
            ))

    def save_public_key(self, path: str):
        """保存公钥到文件"""
        if self._public_key is None:
            raise ValueError("Keys not generated. Call generate_keys() first.")
        with open(path, "wb") as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    def load_private_key(self, path: str, password: bytes | None = None):
        """从文件加载私钥"""
        with open(path, "rb") as f:
            self._private_key = serialization.load_pem_private_key(
                f.read(), password=password, backend=default_backend()
            )
        self._public_key = self._private_key.public_key()

    def load_public_key(self, path: str):
        """从文件加载公钥"""
        with open(path, "rb") as f:
            self._public_key = serialization.load_pem_public_key(
                f.read(), backend=default_backend()
            )

    @staticmethod
    def save_ciphertext(ciphertext: bytes, dir_path: str) -> str:
        """保存密文到二进制文件，返回文件名（Hex前20位）"""
        filename = ciphertext[:10].hex() + ".bin"
        filepath = os.path.join(dir_path, filename)
        with open(filepath, "wb") as f:
            f.write(ciphertext)
        return filename

    @staticmethod
    def load_ciphertext(filepath: str) -> bytes:
        """从文件加载密文"""
        with open(filepath, "rb") as f:
            return f.read()

    @staticmethod
    def list_ciphertext_files(dir_path: str) -> list[str]:
        """List all .bin ciphertext files in directory"""
        if not os.path.exists(dir_path):
            return []
        return [f for f in os.listdir(dir_path) if f.endswith(".bin")]
