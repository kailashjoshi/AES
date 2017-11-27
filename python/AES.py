import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
SECRET = '8!fjVb#GP6V&DX;D'

class AESCBCCipher:
    def __init__(self, key):
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, message):
        message = self.__pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(message)).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self.__unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def __pad(self, s):
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size 
            - len(s) % AES.block_size)

    @staticmethod
    def __unpad(s):
        return s[:-ord(s[len(s)-1:])]

aes = AESCBCCipher(SECRET)
enc = aes.encrypt('TestData')
print enc
dec = aes.decrypt(enc)
print dec