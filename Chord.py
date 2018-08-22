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
import datetime
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
        self.encryptionIndex = []
        for i in range(0, self.M+1):
            self.finger.append(None)
        thread1 = looping(self)
        thread1.start()
        metaDataGuid = hashlib.md5()
        metaDataGuid.update("metaData".encode('utf-8'))
        if not (os.path.isfile(str(int(metaDataGuid.hexdigest(), 16)))):
            f = open(str(int(metaDataGuid.hexdigest(), 16)), 'w+')
            tempJson = []
            json.dump(tempJson, f)
            f.close()
        print("Guid: " + str(guid))

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

    def readMetaData(self):
        metaDataGuid = hashlib.md5()
        metaDataGuid.update("metaData".encode('utf-8'))
        f = open(str(self._guid) + "/repository/" + str(int(metaDataGuid.hexdigest(), 16)), 'r')
        jsonRead = json.load(f)
        f.close()
        return jsonRead

    def writeMetaData(self, token, rawData):
        metaDataGuid = hashlib.md5()
        metaDataGuid.update("metaData".encode('utf-8'))
        if not os.path.isfile(str(self._guid) + "/repository/" + str(int(metaDataGuid.hexdigest(), 16))):
            metaDataTemp = []
            metaReader = open(str(self._guid) + "/repository/" + str(int(metaDataGuid.hexdigest(), 16)), 'w+')
            json.dump(metaDataTemp, metaReader)
            metaReader.close()
        metaData = self.readMetaData()
        newData = {}
        newData[token] = rawData
        metaData.append(newData)
        metaReader = open(str(self._guid) + "/repository/" + str(int(metaDataGuid.hexdigest(), 16)), 'w')
        json.dump(metaData, metaReader)
        metaReader.close()
    
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
            elif intType == "Close":
                return guid > begin or guid <= end

    def printFinger(self):
        for i in self.finger:
            if i == None:
                print("None")
            else:
                print(i.guid)

    def closestPrecedingChord(self, guid):
        if guid != self._guid:
            i = self.M - 1;
            while i > 0:
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

    def locateSuccessor(self, guid, debug = False):
        try:
            if guid == self._guid:
                print ("Error it's the same shit")
            else:
                if self._successor.guid != guid:
##                    if debug:
##                        print("Current Chord: " + str(self.guid) + " guid: " + str(guid) + " successor Chord: " + str(self._successor.guid))
                    if self.inInterval("Close", guid, self._guid, self._successor.guid):
                        return self
                    else:
                        nextSuccessor = self.closestPrecedingChord(guid)
##                        print("Next Successor: " + str(nextSuccessor.guid) + " guid: " + str(guid))
                        return nextSuccessor.locateSuccessor(guid, True)
                else:
                    print("Error, same guid")
        except Exception as e:
            print(str(e))

    def ringAround(self, initial, count):
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

    def chainEncrypt(self, fileName, data, count, chainEncryption, page, token, prevKey = None):
        encryptThread = encryptingProcess(self, fileName, data, count, chainEncryption, page, token, prevKey)
        encryptThread.start()
        encryptThread.join()
        self.encryptionIndex.append(encryptThread)

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

    def upload(self, fileName, message, totalPage, token):
        chainEncryption = []
        self.chainEncrypt(fileName, message, 0, chainEncryption, totalPage, token)
        m = hashlib.md5()
        m.update((fileName + ":" + str(totalPage) + ":3").encode('utf-8'))
        return(str(int(m.hexdigest(), 16)))

    def createPage(self, getMessage, getGuid, getToken, getRSAInfo):
        f = open(str(self._guid) + "/repository/" + str(getGuid), 'wb+')
        f.write(b64decode(getMessage))
        f.close()
        self.writeMetaData(getToken, getRSAInfo)
        print(str(getGuid) + " has been created")

    def removePage(self, guidGet):
        os.remove(str(self._guid) + "\\repository\\" + str(getGuid))
            
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

    def sync(self, token):
        metaData = self.readMetaData()
        for x in metaData:
            for tokenGrab, RSAInfo in x.items():
                if tokenGrab == token:
                    metaData.remove(x)
                    return RSAInfo

class encryptingProcess(threading.Thread):
    def __init__(self, chord, fileName, data, count, chainEncryption, page, token, prevKey = None):
        threading.Thread.__init__(self)
        self.chord = chord
        self.fileName = fileName
        self.data = data
        self.count = count
        self.chainEncryption = chainEncryption
        self.page = page
        self.prevKey = prevKey
        self.token = token

    def run(self):    
        try:
            m = hashlib.md5()
            m.update((self.fileName + ":" + str(self.page) + ":" + str(self.count)).encode('utf-8'))
#            Logger.printLog("Encrypting focus : page = " + str(self.page) + " count = " + str(self.count) + " guid = " + str(int(m.hexdigest(), 16)))
            getChord = self.chord.locateSuccessor(int(m.hexdigest(), 16), True)
            if getChord.guid == self.chord.guid:
                if self.count == constant.MAX_CHAIN_ENCRYPTION:
#                    Logger.printLog("page = " + str(self.page) + " count = MAX")
                    tokenHash = hashlib.md5()
                    combo = str(int(m.hexdigest(), 16)) + ":" + str(self.token)
                    tokenHash.update(combo.encode('utf-8'))
                    getChord.createPage(self.data, int(int(m.hexdigest(), 16)), int(tokenHash.hexdigest(), 16), self.chainEncryption)
                elif self.count == 0:
#                    Logger.printLog("page = " + str(self.page) + " count = 0")
                    newSet = {}
                    RSACipher, cipherText, IV, tag = Encryptor.initialize(self.data)
                    newSet["Set"] = self.count
                    newSet["RSACipher"] = b64encode(RSACipher).decode('utf-8')
                    newSet["IV"] = b64encode(IV).decode('utf-8')
                    newSet["Tag"] = b64encode(tag).decode('utf-8')
                    self.chainEncryption.append(newSet)

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
                    getChord.chainEncrypt(self.fileName, b64encode(cipherText).decode('utf-8'), self.count + 1, self.chainEncryption, self.page, self.token, b64encode(privPem).decode('utf-8'))
                else:
#                    Logger.printLog("page = " + str(self.page) + " count = " + str(self.count))
                    newSet = {}
                    getKey = None
                    if self.count == 1:
                        for x in self.chainEncryption:
                            if x["Set"] == self.count-1:
                                RSACipher, cipherText, IV, tag = Encryptor.chainInitialize(b64decode(x["RSACipher"]), b64decode(self.data), b64decode(x["IV"]), b64decode(x["Tag"]), b64decode(self.prevKey))
                    else:
                        for y in self.chord.keychain:
                            if y["Chord"] == self.prevKey:
                                for x in self.chainEncryption:
                                    if x["Set"] == self.count-1:
                                        RSACipher, cipherText, IV, tag = Encryptor.chainInitialize(b64decode(x["RSACipher"]), b64decode(self.data), b64decode(x["IV"]), b64decode(x["Tag"]), y["Key"])
                    newSet["Set"] = self.count
                    newSet["RSACipher"] = RSACipher
                    newSet["IV"] = IV
                    newSet["Tag"] = tag                
                    self.chainEncryption.append(newSet)
                    getChord.chainEncrypt(self.fileName, cipherText, self.count + 1, self.chainEncryption, self.page, self.token, self.chord._guid)
            else:
                getChord.chainEncrypt(self.fileName, self.data, self.count, self.chainEncryption, self.page, self.token, self.prevKey)
        except Exception as e:
            print(str(e))

        
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
