import os
import glob
import json
import constant
from base64 import b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import asymmetric, hmac, serialization, padding, hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.exceptions import InvalidSignature

def dataDecrypt(cipherText, IV, encKey, hMacKey, tag):
    tempTag = hmac.HMAC(hMacKey, hashes.SHA256(), backend=default_backend())
    tempTag.update(cipherText)
    try:
        tempTag.verify(tag)
        cipher = Cipher(algorithms.AES(encKey), modes.CBC(IV), backend=default_backend())
        cipherDecrypt = cipher.decryptor()
        unpadder = padding.PKCS7(constant.PADDING_BLOCK_SIZE).unpadder()
        plainText = cipherDecrypt.update(cipherText) + cipherDecrypt.finalize()
        plainText = unpadder.update(plainText) + unpadder.finalize()
        return plainText
    except InvalidSignature:
        return None
    
def initialize(RSACipher, cipherText, IV, tag):
    f=open(constant.PRIVATE_PEM, 'rb')
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend()
    )

    key = private_key.decrypt(
        RSACipher,
        asymmetric.padding.OAEP(
            mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encKey = key[:32]
    hMacKey = key[32:]
    IVSend = IV
    plainText = dataDecrypt(cipherText, IVSend, encKey, hMacKey, tag)
    if plainText != None:
        return plainText
