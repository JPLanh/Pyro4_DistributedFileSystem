import os
from base64 import b64decode
import constant
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import serialization, hashes, hmac, asymmetric, padding

def dataEncrypt(message, encKey, hMacKey):
    if len(encKey) == constant.KEY_BYTE_SIZE:
        if len(hMacKey) == constant.KEY_BYTE_SIZE:
            IV = os.urandom(constant.IV_BYTE_SIZE)
            cipher = Cipher(algorithms.AES(encKey), modes.CBC(IV), backend=default_backend())
            cipherEncrypt = cipher.encryptor()
            pad = padding.PKCS7(constant.PADDING_BLOCK_SIZE).padder()
            cipherText = pad.update(message) + pad.finalize()
            cipherText = cipherEncrypt.update(cipherText) + cipherEncrypt.finalize()
            hTag = hmac.HMAC(hMacKey, hashes.SHA256(), backend=default_backend())
            hTag.update(cipherText)
            hTag = hTag.finalize()
            return cipherText, IV, hTag

def initialize(message):
    encKey = os.urandom(constant.KEY_BYTE_SIZE)
    hMacKey = os.urandom(constant.KEY_BYTE_SIZE)
    cipherText, IV, tag = dataEncrypt(message, encKey, hMacKey)
    if cipherText != None:
        f=open(constant.PUBLIC_PEM, 'rb')
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )

        RSACipher = public_key.encrypt(
            encKey+hMacKey,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )
        return RSACipher, cipherText, IV, tag
