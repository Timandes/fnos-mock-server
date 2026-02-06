"""Utility functions for fnOS Mock Server."""

import base64
import secrets
import logging
from pathlib import Path
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


logger = logging.getLogger(__name__)


# 读取固定的测试 RSA 公钥
def _load_fixed_rsa_public_key() -> str:
    """Load the fixed test RSA public key from file."""
    key_path = Path(__file__).parent.parent / 'public_key.pem'
    with open(key_path, 'r') as f:
        return f.read()

_FIXED_RSA_PUBLIC_KEY = _load_fixed_rsa_public_key()


def get_fixed_rsa_public_key() -> str:
    """Get the fixed test RSA public key.

    Returns:
        PEM formatted RSA public key string
    """
    return _FIXED_RSA_PUBLIC_KEY


def generate_random_token(length: int = 32) -> str:
    """Generate a random URL-safe token.

    Args:
        length: Length of token in bytes

    Returns:
        URL-safe base64 encoded token string
    """
    return secrets.token_urlsafe(length)


def generate_session_id() -> str:
    """Generate a random session ID.

    Returns:
        Base32 encoded session ID
    """
    return base64.b32encode(secrets.token_bytes(16)).decode('utf-8').lower()


def generate_encrypted_secret() -> str:
    """Generate a mock encrypted secret for login response.

    Returns:
        Base64 encoded encrypted secret
    """
    # 生成随机 AES 密钥
    aes_key = get_random_bytes(32)

    # 生成随机 IV
    iv = get_random_bytes(16)

    # 生成随机 secret
    secret = secrets.token_bytes(32)

    # 使用 AES 加密 secret
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_secret = pad(secret, AES.block_size)
    encrypted_secret = cipher.encrypt(padded_secret)

    # 返回 base64 编码的结果
    return base64.b64encode(encrypted_secret).decode('utf-8')