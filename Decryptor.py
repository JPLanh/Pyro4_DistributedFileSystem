import os
import glob
import json
import constant
import Logger
from base64 import b64decode, b64encode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import asymmetric, hmac, serialization, padding, hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.exceptions import InvalidSignature

def dataDecrypt(cipherText, IV, encKey, hMacKey):
    cipher = Cipher(algorithms.AES(encKey), modes.CBC(IV), backend=default_backend())
    cipherDecrypt = cipher.decryptor()
    unpadder = padding.PKCS7(constant.PADDING_BLOCK_SIZE).unpadder()
    plainText = cipherDecrypt.update(cipherText) + cipherDecrypt.finalize()
    plainText = unpadder.update(plainText) + unpadder.finalize()
    return plainText

def chainDecryption(message, IVget, encKey, hMacKey, tag):
    checkTag = hmac.HMAC(hMacKey, hashes.SHA256(), backend=default_backend())
    checkTag.update(message)
    try:
        checkTag.verify(tag)
        plainText = dataDecrypt(message, IVget, encKey, hMacKey)
        return plainText
    except InvalidSignature:
        Logger.log("Failed")
        return None
    
def chainInitialize(RSACipher, cipherText, IV, tag, chained = False):
    print("Decryptor chain initialize flag 1")
    if chained:
        print(chained)
        private_key = serialization.load_pem_private_key(
            chained,
            password=None,
            backend=default_backend()
        )
    else:
        print("is not chain")
        f=open(constant.CHORD_PRIV_PEM, 'rb')        
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

    print("Decryptor chain initialize flag 2")
    key = private_key.decrypt(
        RSACipher,
        asymmetric.padding.OAEP(
            mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("Decryptor chain initialize flag 3")
    encKey = key[:32]
    hMacKey = key[32:]
    plainText = chainDecryption(cipherText, IV, encKey, hMacKey, tag)
    print("Decryptor chain initialize flag 4")
    if plainText != None:
        print("Decryptor chain initialize flag 5")
        return b64encode(plainText).decode('UTF-8')
    else:
        print("None returned from decryption")

def initialize(RSACipher, cipherText, IV, tag, chained):
    if chained:
        f=open(constant.CHORD_PRIV_PEM, 'rb')
    else:
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
    plainText = dataDecrypt(cipherText, IV, encKey, hMacKey, tag)
    if plainText != None:
        return b64encode(plainText).decode('UTF-8')
    else:
        Logger.log("None returned from decryption")
