from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
import os
import struct

# 文件加密常量
RSAF_MAGIC = b"RSAF"
RSAF_VERSION = 1
MAX_ENCRYPT_PER_BLOCK = 190  # 每块最大加密数据量
ENCRYPTED_BLOCK_SIZE = 256   # RSA加密后块大小
FILE_HEADER_SIZE = 32        # 文件头固定大小


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

    # ==================== 文件加密相关 ====================

    @staticmethod
    def validate_rsaf_file(filepath: str) -> dict | None:
        """验证并解析 RSAF 文件头，返回元数据或 None"""
        try:
            with open(filepath, "rb") as f:
                # 读取文件头
                header = f.read(FILE_HEADER_SIZE)
                if len(header) < FILE_HEADER_SIZE:
                    return None

                # 解析魔数和版本
                magic = header[:4]
                if magic != RSAF_MAGIC:
                    return None

                version = struct.unpack("<H", header[4:6])[0]
                if version != RSAF_VERSION:
                    return None

                # 解析元数据
                filename_len = struct.unpack("<H", header[6:8])[0]
                file_size = struct.unpack("<Q", header[8:16])[0]
                block_count = struct.unpack("<I", header[16:20])[0]

                # 读取文件名
                filename_bytes = f.read(filename_len)
                try:
                    filename = filename_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    filename = filename_bytes.decode("latin-1")

                return {
                    "version": version,
                    "filename": filename,
                    "file_size": file_size,
                    "block_count": block_count,
                    "total_size": os.path.getsize(filepath),
                }
        except (IOError, struct.error):
            return None

    def encrypt_file(self, src_path: str, dst_path: str,
                     progress_callback=None) -> dict:
        """
        加密文件（CBC 模式）
        Args:
            src_path: 源文件路径
            dst_path: 输出文件路径
            progress_callback: 进度回调函数 (bytes_processed, total_bytes)
        Returns:
            {'bytes': processed_bytes, 'blocks': block_count}
        """
        if not os.path.exists(src_path):
            raise FileNotFoundError(f"Source file not found: {src_path}")

        if self._public_key is None:
            raise ValueError("Keys not generated. Call generate_keys() first.")

        # 读取文件信息
        filename = os.path.basename(src_path)
        file_size = os.path.getsize(src_path)
        block_count = (file_size + MAX_ENCRYPT_PER_BLOCK - 1) // MAX_ENCRYPT_PER_BLOCK

        # 计算总大小并验证
        total_output_size = FILE_HEADER_SIZE + len(filename.encode("utf-8")) + \
                           (block_count + 1) * ENCRYPTED_BLOCK_SIZE

        # 生成随机 IV（190 字节）
        iv = os.urandom(MAX_ENCRYPT_PER_BLOCK)
        iv_encrypted = self.encrypt(iv)

        # 写入输出文件
        with open(src_path, "rb") as fin, open(dst_path, "wb") as fout:
            # 写入文件头
            filename_bytes = filename.encode("utf-8")
            header = (
                RSAF_MAGIC +
                struct.pack("<H", RSAF_VERSION) +
                struct.pack("<H", len(filename_bytes)) +
                struct.pack("<Q", file_size) +
                struct.pack("<I", block_count) +
                b"\x00" * 12  # Reserved
            )
            fout.write(header)
            fout.write(filename_bytes)

            # 写入 IV 块
            fout.write(iv_encrypted)

            # 分块加密
            prev_ciphertext = iv_encrypted
            bytes_processed = 0

            while True:
                chunk = fin.read(MAX_ENCRYPT_PER_BLOCK)
                if not chunk:
                    break

                # CBC 异或
                if bytes_processed == 0:
                    xored = bytes(a ^ b for a, b in zip(chunk, iv))
                else:
                    xored = bytes(a ^ b for a, b in zip(chunk, prev_ciphertext))

                # 填充到 190 字节（如果需要）
                if len(xored) < MAX_ENCRYPT_PER_BLOCK:
                    xored = xored + b"\x00" * (MAX_ENCRYPT_PER_BLOCK - len(xored))

                # RSA 加密
                encrypted = self.encrypt(xored)
                fout.write(encrypted)
                prev_ciphertext = encrypted

                bytes_processed += len(chunk)

                # 回调进度
                if progress_callback:
                    progress_callback(bytes_processed, file_size)

        return {"bytes": bytes_processed, "blocks": block_count}

    def decrypt_file(self, src_path: str, dst_path: str,
                     progress_callback=None) -> dict:
        """
        解密文件（CBC 模式）
        Args:
            src_path: 加密文件路径
            dst_path: 输出文件路径
            progress_callback: 进度回调函数 (bytes_processed, total_bytes)
        Returns:
            {'filename': original_filename, 'size': file_size}
        """
        if not os.path.exists(src_path):
            raise FileNotFoundError(f"Encrypted file not found: {src_path}")

        if self._private_key is None:
            raise ValueError("Keys not generated. Call generate_keys() first.")

        # 验证文件格式
        metadata = self.validate_rsaf_file(src_path)
        if metadata is None:
            raise ValueError("Invalid RSAF file format")

        file_size = metadata["file_size"]
        block_count = metadata["block_count"]
        original_filename = metadata["filename"]

        with open(src_path, "rb") as fin, open(dst_path, "wb") as fout:
            # 跳过文件头和文件名
            fin.seek(FILE_HEADER_SIZE + len(original_filename.encode("utf-8")))

            # 读取并解密 IV 块
            iv_encrypted = fin.read(ENCRYPTED_BLOCK_SIZE)
            iv = self.decrypt(iv_encrypted)

            # 分块解密
            prev_ciphertext = iv_encrypted
            bytes_processed = 0

            for i in range(block_count):
                encrypted_block = fin.read(ENCRYPTED_BLOCK_SIZE)
                decrypted = self.decrypt(encrypted_block)

                # 逆 CBC 异或
                if i == 0:
                    xored = bytes(a ^ b for a, b in zip(decrypted, iv))
                else:
                    xored = bytes(a ^ b for a, b in zip(decrypted, prev_ciphertext))

                prev_ciphertext = encrypted_block

                # 去除填充，保留原始数据
                if i == block_count - 1 and file_size % MAX_ENCRYPT_PER_BLOCK != 0:
                    actual_len = file_size % MAX_ENCRYPT_PER_BLOCK
                    xored = xored[:actual_len]

                fout.write(xored)
                bytes_processed += len(xored)

                # 回调进度
                if progress_callback:
                    progress_callback(bytes_processed, file_size)

        return {"filename": original_filename, "size": file_size}

    @staticmethod
    def get_ciphertext_filename(ciphertext_bytes: bytes) -> str:
        """生成密文文件名（取密文前10位Hex + .rsa后缀）"""
        return ciphertext_bytes[:10].hex() + ".rsa"
