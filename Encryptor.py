import os
from base64 import b64encode, b64decode
import constant
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import serialization, hashes, hmac, asymmetric, padding
from cryptography.exceptions import InvalidSignature
import hashlib
import Logger

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

def chainEncryption(message, tag, encKey, hMacKey):
    print("Debug flag 1.2.1")
    checkTag = hmac.HMAC(hMacKey, hashes.SHA256(), backend=default_backend())
    checkTag.update(message)
    print("Debug flag 1.2.2")
    try:
        print("Debug flag 1.2.3")
        checkTag.verify(tag)
        newEncKey = os.urandom(constant.KEY_BYTE_SIZE)
        newHMacKey = os.urandom(constant.KEY_BYTE_SIZE)
        cipherText, newIV, newHTag = dataEncrypt(message, newEncKey, newHMacKey)
        return cipherText, newIV, newHTag, newEncKey, newHMacKey
    except InvalidSignature:
        print("Failed")
        return None
    
def chainInitialize(RSACipher, cipherText, IV, tag, prevKey):
    Logger.printLog("Chain Initialize Flag 1")
    private_key = serialization.load_pem_private_key(
        prevKey,
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
    
    Logger.printLog("Chain Initialize Flag 2")
    encKey = key[:32]
    hMacKey = key[32:]

    Logger.printLog("Chain Initialize Flag 3")
    newCipher, newIV, newTag, newEncKey, newHMacKey = chainEncryption(cipherText, tag, encKey, hMacKey)

    Logger.printLog("Chain Initialize Flag 4")
    f=open(constant.CHORD_PUB_PEM, 'rb')
    public_key = serialization.load_pem_public_key(
        f.read(),
        backend=default_backend()
    )

    f.close()

    RSACipher = public_key.encrypt(
        newEncKey+newHMacKey,
        asymmetric.padding.OAEP(
            mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )
    return b64encode(RSACipher).decode('UTF-8'), b64encode(newCipher).decode('UTF-8'), b64encode(newIV).decode('UTF-8'), b64encode(newTag).decode('UTF-8')   

def initialize(message):
    print("Debug flag 1.1")
    encKey = os.urandom(constant.KEY_BYTE_SIZE)
    hMacKey = os.urandom(constant.KEY_BYTE_SIZE)
    print("Debug flag 1.2")
    cipherText, IV, tag = dataEncrypt(b64decode(message), encKey, hMacKey)
    print("Debug flag 1.3")
    if cipherText != None:
        f=open(constant.CHORD_PUB_PEM, 'rb')
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
        print("Debug flag 1.4")
        print(public_key)

        RSACipher = public_key.encrypt(
            encKey+hMacKey,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )
        print("Debug flag 1.5")

        return RSACipher, cipherText, IV, tag
