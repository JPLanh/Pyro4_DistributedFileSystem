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

def dataDecrypt(cipherText, IV, encKey):
    cipher = Cipher(algorithms.AES(encKey), modes.CBC(IV), backend=default_backend())
    cipherDecrypt = cipher.decryptor()
    unpadder = padding.PKCS7(constant.PADDING_BLOCK_SIZE).unpadder()
    plainText = cipherDecrypt.update(cipherText) + cipherDecrypt.finalize()
    plainText = unpadder.update(plainText) + unpadder.finalize()
    return plainText

def dataDecryption(message, IVget, encKey, hMacKey, tag):
    checkTag = hmac.HMAC(hMacKey, hashes.SHA256(), backend=default_backend())
    checkTag.update(message)
    try:
        checkTag.verify(tag)
        plainText = dataDecrypt(message, IVget, encKey)
        return plainText
    except InvalidSignature:
        print("invalid signature")
        return None
                   
def chainDecryption(message, IVget, encKey, hMacKey, tag):
    checkTag = hmac.HMAC(hMacKey, hashes.SHA256(), backend=default_backend())
    checkTag.update(message)
    try:
        checkTag.verify(tag)
        plainText = dataDecrypt(message, IVget, encKey)
        return plainText
    except InvalidSignature:
        print("invalid signature")
        return None
    
def chainInitialize(RSACipher, cipherText, IV, tag, key):
    f=open(constant.CHORD_PRIV_PEM, 'rb')        
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
    plainText = chainDecryption(cipherText, IV, encKey, hMacKey, tag)
    if plainText != None:
        return b64encode(plainText).decode('UTF-8')
    else:
        print("None returned from decryption")

def initialize(RSACipher, cipherText, IV, tag, client = False):
    if client:        
        f=open(constant.PRIVATE_PEM, 'rb')        
    else:
        f=open(constant.CHORD_PRIV_PEM, 'rb')
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
    plainText = dataDecryption(cipherText, IV, encKey, hMacKey, tag)
    if plainText != None:
        return b64encode(plainText).decode('UTF-8')
    else:
        Logger.log("None returned from decryption")
