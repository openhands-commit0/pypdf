from pypdf._crypt_providers._base import CryptBase
from pypdf.errors import DependencyError
_DEPENDENCY_ERROR_STR = 'cryptography>=3.1 is required for AES algorithm'
crypt_provider = ('local_crypt_fallback', '0.0.0')

def aes_cbc_decrypt(key: bytes, data: bytes, iv: bytes = bytes(16)) -> bytes:
    raise DependencyError(_DEPENDENCY_ERROR_STR)

def aes_cbc_encrypt(key: bytes, data: bytes, iv: bytes = bytes(16)) -> bytes:
    raise DependencyError(_DEPENDENCY_ERROR_STR)

def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    raise DependencyError(_DEPENDENCY_ERROR_STR)

def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    raise DependencyError(_DEPENDENCY_ERROR_STR)

class CryptRC4(CryptBase):

    def __init__(self, key: bytes) -> None:
        self.s = bytearray(range(256))
        j = 0
        for i in range(256):
            j = (j + self.s[i] + key[i % len(key)]) % 256
            self.s[i], self.s[j] = (self.s[j], self.s[i])

    def encrypt(self, data: bytes) -> bytes:
        s = self.s.copy()
        i = j = 0
        out = bytearray()
        for byte in data:
            i = (i + 1) % 256
            j = (j + s[i]) % 256
            s[i], s[j] = s[j], s[i]
            k = s[(s[i] + s[j]) % 256]
            out.append(byte ^ k)
        return bytes(out)

    def decrypt(self, data: bytes) -> bytes:
        return self.encrypt(data)

class CryptAES(CryptBase):

    def __init__(self, key: bytes) -> None:
        raise DependencyError(_DEPENDENCY_ERROR_STR)

    def encrypt(self, data: bytes) -> bytes:
        raise DependencyError(_DEPENDENCY_ERROR_STR)

    def decrypt(self, data: bytes) -> bytes:
        raise DependencyError(_DEPENDENCY_ERROR_STR)