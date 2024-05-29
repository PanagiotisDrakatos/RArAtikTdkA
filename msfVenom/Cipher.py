import base64
import hashlib
from Crypto.Cipher import AES
from pkcs7 import PKCS7Encoder
from Crypto.Util.Padding import pad, unpad
class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode("utf-8")).digest()
        self._encoder=PKCS7Encoder()
        self._iv= "Y0Xu7RihlxKo47mz".encode("utf-8")

    def encrypt(self, raw):
        raw = pad(raw.encode("utf-8"),AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, self._iv)
        cipher_text = cipher.encrypt(raw)
        return base64.b64encode(cipher_text).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_CBC, self._iv)
        return unpad(cipher.decrypt(enc),AES.block_size).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]