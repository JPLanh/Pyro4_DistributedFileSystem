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
    print("Encryption Data Encrypt: 1")
    if len(encKey) == constant.KEY_BYTE_SIZE:
        if len(hMacKey) == constant.KEY_BYTE_SIZE:
            print(message)
            print("Encryption Data Encrypt: 2")
            IV = os.urandom(constant.IV_BYTE_SIZE)
            print("Encryption Data Encrypt: 3")
            cipher = Cipher(algorithms.AES(encKey), modes.CBC(IV), backend=default_backend())
            print("Encryption Data Encrypt: 4")
            cipherEncrypt = cipher.encryptor()
            print("Encryption Data Encrypt: 5")
            pad = padding.PKCS7(constant.PADDING_BLOCK_SIZE).padder()
            print("Encryption Data Encrypt: 6")
            cipherText = pad.update(message) + pad.finalize()
            print("Encryption Data Encrypt: 7")
            cipherText = cipherEncrypt.update(cipherText) + cipherEncrypt.finalize()
            print("Encryption Data Encrypt: 8")
            hTag = hmac.HMAC(hMacKey, hashes.SHA256(), backend=default_backend())
            print("Encryption Data Encrypt: 9")
            hTag.update(cipherText)
            print("Encryption Data Encrypt: 10")
            hTag = hTag.finalize()
            print("Encryption Data Encrypt: 11")
            print(cipherText)
            return cipherText, IV, hTag

def chainEncryption(message, tag, encKey, hMacKey):
    checkTag = hmac.HMAC(hMacKey, hashes.SHA256(), backend=default_backend())
    checkTag.update(message)
    try:
        checkTag.verify(tag)
        newEncKey = os.urandom(constant.KEY_BYTE_SIZE)
        newHMacKey = os.urandom(constant.KEY_BYTE_SIZE)
        cipherText, newIV, newHTag = dataEncrypt(message, newEncKey, newHMacKey)
        return cipherText, newIV, newHTag, newEncKey, newHMacKey
    except InvalidSignature:
        print("Failed")
        return None
    
def chainInitialize(RSACipher, cipherText, IV, tag, prevKey):
    print("RSACipher: " + RSACipher)
    print("CipherText: " +cipherText)
    print("IV: " + IV)
    print("tag: " + tag)
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
    
    encKey = key[:32]
    hMacKey = key[32:]
        
    newCipher, newIV, newTag, newEncKey, newHMacKey = chainEncryption(cipherText, tag, encKey, hMacKey)

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
    print("Encryption Initalize: 1")
    encKey = os.urandom(constant.KEY_BYTE_SIZE)
    hMacKey = os.urandom(constant.KEY_BYTE_SIZE)
    print("Encryption Initalize: 2")
    cipherText, IV, tag = dataEncrypt(b64decode(message), encKey, hMacKey)
    print("Encryption Initalize: 3")
    if cipherText != None:
        f=open(constant.CHORD_PUB_PEM, 'rb')
        print("Encryption Initialize: 4")
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
        print("Encryption Initialize: 5")

        RSACipher = public_key.encrypt(
            encKey+hMacKey,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )
        print("Encryption Initialize: 6")
        return RSACipher, cipherText, IV, tag
