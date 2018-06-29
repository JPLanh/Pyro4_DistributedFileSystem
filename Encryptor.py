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
    Logger.log("Flag 4.5.1")
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
    Logger.log("Flag 4.1")
    checkTag = hmac.HMAC(hMacKey, hashes.SHA256(), backend=default_backend())
    Logger.log("Flag 4.2")
    checkTag.update(message)
    Logger.log("Flag 4.3")
    try:
        Logger.log("Flag 4.4")
        checkTag.verify(tag)
        Logger.log("Flag 4.5")
        newEncKey = os.urandom(constant.KEY_BYTE_SIZE)
        newHMacKey = os.urandom(constant.KEY_BYTE_SIZE)
        cipherText, newIV, newHTag = dataEncrypt(message, newEncKey, newHMacKey)
        return cipherText, newIV, newHTag, newEncKey, newHMacKey
    except InvalidSignature:
        Logger.log("Failed")
        return None
    
def chainInitialize(RSACipher, cipherText, IV, tag, prevKey):
    Logger.log("Flag 1.8.1")
#    f=open(constant.PRIVATE_PEM, 'rb')

    f = open("./testKey", 'wb+')
    Logger.log("Flag 1.8.1.1")
    f.write(prevKey)
    Logger.log("Flag 1.8.1.2")
    f.close()
    f = open("./testKey", 'rb')
    

    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend()
    )
    Logger.log("Flag 1.8.2")

#    f.close()
    Logger.log(str(len(RSACipher)))
             
    key = private_key.decrypt(
        RSACipher,
        asymmetric.padding.OAEP(
            mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    Logger.log("Flag 1.8.3")
    
    encKey = key[:32]
    hMacKey = key[32:]
    
    Logger.log("Flag 1.8.4")
    newCipher, newIV, newTag, newEncKey, newHMacKey = chainEncryption(cipherText, tag, encKey, hMacKey)

    Logger.log("Flag 1.8.5")
    f=open(constant.CHORD_PUB_PEM, 'rb')
    public_key = serialization.load_pem_public_key(
        f.read(),
        backend=default_backend()
    )

    f.close()

    Logger.log("Flag 1.8.6")
    RSACipher = public_key.encrypt(
        newEncKey+newHMacKey,
        asymmetric.padding.OAEP(
            mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )
    
    Logger.log("Flag 1.8.7")

    return RSACipher, cipherText, newIV, newTag   

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
