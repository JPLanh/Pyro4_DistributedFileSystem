import os
from base64 import b64decode
import constant
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import serialization, hashes, hmac, asymmetric, padding
from cryptography.exceptions import InvalidSignature
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
        return cipherText, newIV, newHTag, newEncKey, hMacKey
    except InvalidSignature:
        Logger.log("Failed")
        return None

def chainInitialize(message):
    Logger.log("Flag 1")
    RSACipher, cipherText, IV, tag = initialize(message)
    Logger.log("Flag 2")
    return encryptChaining(RSACipher, cipherText, IV, tag, 0)
    
def encryptChaining(RSACipher, cipherText, IV, tag, count):
    Logger.log("Flag 3")
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

    mid = int(len(key)/2)
    Logger.log(str(mid))
    encKey = key[:mid]
    hMacKey = key[mid:]

    Logger.log("Flag 4")
    Logger.log(str(cipherText))
    newCipher, newIV, newTag, newEnc, newHMac = chainEncryption(cipherText, tag, encKey[:32], hMacKey[:32])
    Logger.log(str(newCipher))
    Logger.log("Flag 5")

    combEncKey = newEnc + encKey
    combHMacKey = newHMac + hMacKey
    combIV = newIV + IV

    if newCipher != None:
        Logger.log("Flag 6")
        f=open(constant.PUBLIC_PEM, 'rb')
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )

        RSACipher = public_key.encrypt(
            combEncKey+combHMacKey,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )

    
    Logger.log("Flag 7")
    if count == constant.MAX_CHAIN_ENCRYPTION:        
        Logger.log("Flag 8")
        return RSACipher, newCipher, combIV, combTag
    else:
        Logger.log("Flag 9")
        return encryptChaining(RSACipher, newCipher, combIV, newTag, count + 1)
   

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
