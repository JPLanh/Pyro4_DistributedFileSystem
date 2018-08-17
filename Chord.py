import hashlib
import ctypes
import os
import Pyro4
from Pyro4 import naming
import logging
import json
import threading
import constant
import Encryptor
import Decryptor
import time
import Logger
import glob
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import serialization, hashes, hmac, asymmetric, padding
from base64 import b64encode, b64decode

@Pyro4.expose
class Chord(object):
    def __init__(self, ip, port, guid):
        self.M = 3
        self._ip = ip
        self._port = port
        self._guid = guid
        self._successor = self
        self._predecessor = None
        self.finger = []
        self.nextFinger = 0
        self.keychain = []
        self.active = 1
        for i in range(0, self.M+1):
            self.finger.append(None)
        thread1 = looping(self)
        thread1.start()

    @property
    def ip(self):
        return self._ip

    @property
    def port(self):
        return self._port

    @property
    def guid(self):
        return self._guid

    @property
    def remoteGuid(self):
        return b64encode(self._guid).decode('UTF-8')        

    @property
    def chord(self):
        return self._chord

    @property
    def successor(self):
        return self._successor

    @property
    def predecessor(self):
        return self._predecessor

    def joinRing(self, getIp, getPort, guid):
        try:
            with Pyro4.locateNS(host=getIp, port=int(getPort)-1) as ns:
                for guidGet, guidURI in ns.list(prefix=str(guid)).items():
                    chordGet = Pyro4.Proxy(guidURI)
                    self._predecessor = None
                    self._successor = chordGet.locateSuccessor(self._guid)
                    self.stabilize()
                    self.fixFinger()
                    self.checkPredecessor()
                    self._successor.stabilize()
                    self._successor.fixFinger()
                    self._successor.checkPredecessor()
    ##                self.exchangeKey(self, self._successor)
                    self._successor.keyEstablish(self, self._successor, self._guid)
                    return ("Connected to %s:%s (%s)" %(self._successor.ip, self._successor.port, chordGet.guid))
        except Exception as e:
            print(str(e))

    def echo(self, message):
        print(message)

    def createKeys(self):
        privateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        privPem = privateKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ) 

        pubKey = privateKey.public_key()
        pubPem = pubKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return b64encode(privPem).decode('UTF-8'), b64encode(pubPem).decode('UTF-8')

    def keyEstablish(self, predecessorChord, currentChord, getGuid):
        for x in self.keychain:
            if x["Chord"] == getGuid:
                break
        predecessorChord.exchangeKeyTwo(predecessorChord, currentChord)
        
    def exchangeKeyTwo(self, currentChord, nextChord, exchanged = False):
        f=open(constant.CHORD_PRIV_PEM, 'rb')
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
        privPem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        f.close()
        nextChord.addKey(currentChord, b64encode(privPem).decode('UTF-8'))
        if not exchanged:                
            nextChord.exchangeKeyTwo(nextChord, currentChord, True)
            if currentChord.guid != nextChord.successor.guid:
                nextChord.exchangeKeyTwo(currentChord, nextChord._successor)
        
    def exchangeKey(self, currentChord, nextChord, exchanged = False):
        if nextChord.hasKey(currentChord) == "False":
            f=open(constant.CHORD_PRIV_PEM, 'rb')
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
            privPem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            f.close()
            nextChord.addKey(currentChord, b64encode(privPem).decode('UTF-8'))
            if not exchanged:                
                nextChord.exchangeKey(nextChord, currentChord, True)
                if currentChord.guid != nextChord.successor.guid:
                    return nextChord.exchangeKey(currentChord, nextChord.successor)

    def hasKey(self, chordGet):
        for x in self.keychain:
            if x["Chord"] == chordGet.guid:
                return "True"
        return "False"
    
    def addKey(self, chordGet, keyGet):
        key = {}
        key["Chord"] = chordGet.guid
        key["Key"] = b64decode(keyGet)
        self.keychain.append(key)

    def keyPrint(self):
        for x in self.keychain:
            print(str(x))        

    def stabilize(self):
        if self._successor != None:
            try:
                x = self._successor.predecessor
                if x != None and x.guid != self._guid and self.inInterval("Close", x.guid, self._guid, self._successor.guid):
                    self._successor = x
                if self._successor.guid != self._guid:
                    self._successor.notify(self)
            except Exception as e:
                pass
            
    def notify(self, chord):
        if self._predecessor == None:
            self._predecessor = chord
        else:
            if self.inInterval("Close", chord.guid, self._predecessor.guid, self._guid):
                self._predecessor = chord
                            
    def fixFinger(self):
        self.nextFinger = (self.nextFinger + 1)
        if self.nextFinger > self.M:
            self.nextFinger = 1
        nextGuid = self._guid + (1 << (self.nextFinger-1))
        self.finger[self.nextFinger] = self.locateSuccessor(nextGuid)
    
    def isAlive(self):
        return True
    
    def checkPredecessor(self):
        try:
            if self._predecessor != None:
                if not self._predecessor.isAlive():
                    self._predecessor = None
        except:
            self._predecessor = None

    def inInterval(self, intType, guid, begin, end):
        if begin < end:
            if intType == "Open":
                return guid > begin and guid < end
            elif intType == "Close":
                return guid > begin and guid <= end                
        else:
            if intType == "Open":
                return guid > begin or guid < end
            if intType == "Close":
                return guid > begin or guid <= end

    def printFinger(self):
        for i in self.finger:
            if i == None:
                print("None")
            else:
                print(i.guid)

    def closestPrecedingChord(self, guid):
        print("In closest proceeding chord")
        print("guid: " + guid + " self: " + self._guid)
        if guid != self._guid:
            i = self.M - 1;
            while i >= 0:
                print(str(i))
                if self.inInterval("Open", self.finger[i].guid, self._guid, guid):
                    if self.finger[i].guid != guid:
                        return self.finger[i]
                i -= 1
            return self._successor

    def simplePrint(self):
        if self._predecessor != None:
            return ("S: %s C: %s P: %s" %(self._successor.guid, self.guid, self._predecessor.guid))
        else:
            return ("S: %s C: %s P: %s" %(self._successor.guid, self.guid, self._predecessor))

    def replaceKey(self):
        files = os.listdir(str(self._guid) + "\\repository\\")
        for x in files:
            print(x)
        
    def locateSuccessor(self, guid):
        if guid == self._guid:
            print ("Error it's the same shit")
        else:
            try:
                if self._successor.guid != guid:
                    if self.inInterval("Close", guid, self._guid, self._successor.guid):
                        return self._successor
                    else:
                        print("Locate 2")
                        nextSuccessor = self._successor.closestPrecedingChord(guid)
                        print(nextSuccessor)
                        return nextSuccessor.locateSuccessor(guid)
            except Exception as e:
                print(str(e))

    def readMetaData(self):
        m = hashlib.md5()
        m.update("MetaData".encode('utf-8'))
        meta = int(m.hexdigest(), 16)
        jread = open(constant.USB_DIR+str(meta), 'r')
        jsonRead = json.load(jread)
        return jsonRead["metadata"]

    def writeMetaData(self, rawData):
        m = hashlib.md5()
        m.update("MetaData".encode('utf-8'))
        meta = int(m.hexdigest(), 16)
        f = open(constant.USB_DIR+str(meta), 'w')
        metadata = {}
        metadata['metadata'] = rawData
        json.dump(metadata, f)
        f.close()

    def ringAround(self, initial, count):
        print(self.simplePrint())
        if self.guid == self._successor.guid:
            return 1
        if self.guid != initial.guid:
            return self._successor.ringAround(initial, count+1)
        else:
            return count            
        
    def newFile(self, file):
        f = open(file, 'rb')
        data = f.read()
        f.close()
        fileInfo = {}
        fileInfo['File Name'] = file
        fileInfo['Total Pages'] = 0
        fileInfo['Page Size'] = self.calculateSize(len(data))
        fileInfo['File Size'] = 0
        pages = []
        fileInfo['Pages'] = pages
        return fileInfo

    def chainEncrypt(self, fileName, data, count, chainEncryption, page, prevKey = None):
        try:
            print("Encrypting focus : count = " + str(count))
            m = hashlib.md5()
            print("Ready?")
            m.update((fileName + ":" + str(page) + ":" + str(count)).encode('utf-8'))
            print(str(int(m.hexdigest(), 16)))
            getChord = self.locateSuccessor(int(m.hexdigest(), 16))
            print("Reach")
            if count == constant.MAX_CHAIN_ENCRYPTION:
                print("Count = max")
                return str(int(m.hexdigest(), 16)), data, chainEncryption
            elif count == 0:
                print("Count = 0")
                newSet = {}
                RSACipher, cipherText, IV, tag = Encryptor.initialize(data)
                newSet["Set"] = count
                newSet["RSACipher"] = b64encode(RSACipher).decode('utf-8')
                newSet["IV"] = b64encode(IV).decode('utf-8')
                newSet["Tag"] = b64encode(tag).decode('utf-8')
                chainEncryption.append(newSet)

                f=open(constant.PRIVATE_PEM, 'rb')
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
                privPem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
                return getChord.chainEncrypt(fileName, b64encode(cipherText).decode('utf-8'), count + 1, chainEncryption, page, b64encode(privPem).decode('utf-8'))
            else:
                print("Encryption flag test 1")                
                newSet = {}
                getKey = None
                if count == 1:
                    print("Encryption flag test 2.1")
                    for x in chainEncryption:
                        if x["Set"] == count-1:
                            RSACipher, cipherText, IV, tag = Encryptor.chainInitialize(b64decode(x["RSACipher"]), b64decode(data), b64decode(x["IV"]), b64decode(x["Tag"]), b64decode(prevKey))
                else:
                    print("Encryption flag test 2.2")
                    for y in self.keychain:
                        if y["Chord"] == prevKey:
                            for x in chainEncryption:
                                if x["Set"] == count-1:
                                    RSACipher, cipherText, IV, tag = Encryptor.chainInitialize(b64decode(x["RSACipher"]), b64decode(data), b64decode(x["IV"]), b64decode(x["Tag"]), b64decode(y["Key"]))
                print("Encryption flag test 3")
                newSet["Set"] = count
                newSet["RSACipher"] = RSACipher
                newSet["IV"] = IV
                newSet["Tag"] = tag
                chainEncryption.append(newSet)
                print("Encryption flag test 4")
                return getChord.chainEncrypt(fileName, cipherText, count + 1, chainEncryption, page, self._guid)
        except Exception as e:
            print(str(e))

##    def chainDecryption(self, fileName, data, count, RSAInfo, page = False):
##        for x in RSAInfo:            
##            m.update((fileName + ":" + str(pageGet) + ":" + str(x['Set'])).encode('utf-8'))
##            getChord = self.locateSuccessor(int(m.hexdigest(), 16))
##            if x['Set'] == 2:
##        for x in RSAInfo:
##            if x["Set"] == count:
##                RSACipher = x["RSACipher"]
##                IV = x["IV"]
##                tag = x["Tag"]
##        if count == 0:
##            return Decryptor.initialize(b64decode(RSACipher), b64decode(data), b64decode(IV), b64decode(tag), False)
##        else:
##            if count == constant.MAX_CHAIN_ENCRYPTION-1:
##                cipherText = Decryptor.initialize(b64decode(RSACipher), data, b64decode(IV), b64decode(tag), True)
##            else:
##                cipherText = Decryptor.initialize(b64decode(RSACipher), b64decode(data), b64decode(IV), b64decode(tag), True)
##            return self.chainDecryption(fileName, cipherText, count - 1, RSAInfo, page)

    def chainDecrypt(self, fileName, data, pageGet, count, RSAInfo, page = False):
        for x in b64decode(RSAInfo):
            if x['Set'] == count:
                RSACipher = x["RSACipher"]
                IV = x["IV"]
                tag = x["Tag"]
        if count == constant.MAX_CHAIN_ENCRYPTION-1:
            newData = Decryptor.chainInitialize(b64decode(RSACipher), b64decode(data), b64decode(IV), b64decode(tag), False)
            m.update((fileName + ":" + str(pageGet) + ":" + (count-1)).encode('utf-8'))
            getChord = self.locateSuccessor(int(m.hexdigest(), 16))
            return getChord.chainDecrypt(fileName, b64encode(newData).decode('UTF-8'), pageGet, count-1, b64encode(RSAInfo).decode('UTF-8'), False)
        else:
            if count == 0:
                return Decryptor.chainInitialize(b64decode(RSACipher), b64decode(data), b64decode(IV), b64decode(tag), True)
            else:
                newData = Decryptor.chainInitialize(b64decode(RSACipher), b64decode(data), b64decode(IV), b64decode(tag), True)
                m.update((fileName + ":" + str(pageGet) + ":" + (count-1)).encode('utf-8'))
                getChord = self.locateSuccessor(int(m.hexdigest(), 16))
                return getChord.chainDecrypt(fileName, newData, pageGet, count - 1, RSAInfo, page)
        
    def download(self, fileName, guidGet, pageGet, RSAInfo):
        getChord = self.locateSuccessor(guidGet)
        data = getChord.readData(guidGet)
        return self.chainDecrypt(fileName, data, pageGet, 2, RSAInfo, True)

    def readData(self, guidGet):
        return b64encode(open(guidGet, 'rb')).decode('UTF-8')

    def upload(self, fileName, message, totalPage):
        chainEncryption = []
        fileGuid, cipherText, RSAInfo = self.chainEncrypt(fileName, message, 0, chainEncryption, totalPage)
        chordGet = self.locateSuccessor(int(fileGuid))
        chordGet.createPage(cipherText, int(fileGuid))
        return fileGuid, RSAInfo
        
    def append(self, file):
        metadata = self.readMetaData()
        for x in metadata:
            if x['File Name'] == file:
                f = open(file, 'rb')
                data = f.read()
                f.close()
                byteRead = x['File Size']
                newPage = {}
                m = hashlib.md5()
                IPGet = file + ":" + str(x['Total Pages'])
                m.update(IPGet.encode('utf-8'))
                newPage["Page"] = x['Total Pages']
                x['Total Pages'] += 1
                chordGet = self.locateSuccessor(int(m.hexdigest(), 16))
                chainEncryption = []
                if (len(data)-byteRead) > x['Page Size']:
                  fileGuid, cipherText, RSAInfo = chordGet.chainEncrypt(file, data[byteRead:(byteRead+x['Page Size'])], 0, chainEncryption, x['Total Pages']) 
                  newPage["Size"] = x['Page Size']
                  x['File Size'] += x['Page Size']
                else:
                  fileGuid, cipherText, RSAInfo = chordGet.chainEncrypt(file, data[byteRead:len(data)], 0, chainEncryption, x['Total Pages']) 
                  newPage["Size"] = len(data)-byteRead
                  x['File Size'] += len(data)-byteRead
                newPage["Guid"] = fileGuid
                newPage["RSAInfo"] = RSAInfo
                chordGet.createPage(cipherText, fileGuid)
                x['Pages'].append(newPage)          
                self.writeMetaData(metadata)
                return round((byteRead / len(data)) * 100)

    def removePage(self, guidGet):
        os.remove(guidGet)
            
    def ls(self):
        metadata = self.readMetaData()
        array = []
        for x in metadata:
            array.append("%s  |  %s  |  %s" %(x['File Name'], x['File Size'], x['Total Pages']))
        return array
        
    def calculateSize(self, getSize):
        cutSize = getSize / (self.ringAround(self._successor, 0)*5)
        return 2**self.findBinary(cutSize, 0)

    def findBinary(self, getSize, count):
        if getSize < 2:
            return count
        else:
            return self.findBinary(getSize/2, count+1)

    def getServerStatus(self):
        return self.active

    def shutDown(self, master):
        self.active = 0
        if self != master:
            self._successor.shutDown(master)

class looping(threading.Thread):
    def __init__(self, chord):
        threading.Thread.__init__(self)
        self.chord = chord

    def run(self):
        while True:
            self.chord.stabilize()
            self.chord.fixFinger()
            self.chord.checkPredecessor()
            time.sleep(2)
