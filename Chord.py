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

#Starts up a node
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

        metaDataGuid = hashlib.md5()
        metaDataGuid.update("metaData".encode('utf-8'))
        if not (os.path.isfile(str(int(metaDataGuid.hexdigest(), 16)))):
            f = open(str(int(metaDataGuid.hexdigest(), 16)), 'w+')
            tempJson = []
            json.dump(tempJson, f)
            f.close()
        thread1 = looping(self)
        thread1.start()
        print("Guid: " + str(guid))

#some properties of the chords that can be recieved by others
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

#Node joins into a ring
    def joinRing(self, getIp, getPort):
        try:
            with Pyro4.locateNS(host="35.212.249.77", port=int(getPort)) as ns:
                joined = False
                for guidGet, guidURI in ns.list().items():
                    if guidGet != "Pyro.NameServer":
                        try:
                            chordGet = Pyro4.Proxy(guidURI)
                            if chordGet.ip != getIp:
                                self._predecessor = None
                                self._successor = chordGet.locateSuccessor(self._guid)
                                self.stabilize()
                                self.fixFinger()
                                self.checkPredecessor()
                                self._successor.stabilize()
                                self._successor.fixFinger()
                                self._successor.checkPredecessor()
    ##                          self.exchangeKey(self, self._successor)
                                self._successor.keyEstablish(self, self._successor, self._guid)
                                return ("Connected to %s:%s (%s)" %(self._successor.ip, self._successor.port, chordGet.guid))
                        except Exception as e:
                            print(e)
                return ("Unable to join any ring")
        except Exception as e:
            return ("An error occured while joining")
                
#Loads the metadata from the node's repository
    def readMetaData(self):
        metaDataGuid = hashlib.md5()
        metaDataGuid.update("metaData".encode('utf-8'))
        f = open(str(self._guid) + "/repository/" + str(int(metaDataGuid.hexdigest(), 16)), 'r')
        jsonRead = json.load(f)
        f.close()
        return jsonRead

#Updates the metadata from the node's repository
    def writeMetaData(self, meta):
        metaDataGuid = hashlib.md5()
        metaDataGuid.update("metaData".encode('utf-8'))
        metaReader = open(str(self._guid) + "/repository/" + str(int(metaDataGuid.hexdigest(), 16)), 'w')
        json.dump(meta, metaReader)
        metaReader.close()

        
    def writeMetaDataOld(self, token, rawData):
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

#Debug so other can have the node they're talking to display a message  
    def echo(self, message):
        print(message)

#Have the node generate a new key and then return those information
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

#A recursive method that exchange a key between nodes, and it will stop once it reaches itself
    def keyEstablish(self, predecessorChord, currentChord, getGuid):
        for x in self.keychain:
            if x["Chord"] == getGuid:
                break
        predecessorChord.exchangeKeyTwo(predecessorChord, currentChord)

#Helper class to exchange the key between two nodes, and save it into their keychain        
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

#Helper class to exchange the key between two nodes, and save it into their keychain                
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

#Check to make sure the node has the key of the other node
    def hasKey(self, chordGet):
        for x in self.keychain:
            if x["Chord"] == chordGet.guid:
                return "True"
        return "False"

#Add a key to the node's keychain    
    def addKey(self, chordGet, keyGet):
        key = {}
        key["Chord"] = chordGet.guid
        key["Key"] = b64decode(keyGet)
        self.keychain.append(key)

#Debugging purposes, print out all keys
    def keyPrint(self):
        for x in self.keychain:
            print(str(x))        

#Update the node's successor
    def stabilize(self):
        if self._successor != None:
            try:
                x = self._successor.predecessor
                if x != None and x.guid != self._guid and self.inInterval("Close", x.guid, self._guid, self._successor.guid):
                    self._successor = x
                if self._successor.guid != self._guid:
                    self._successor.notify(self)
            except Pyro4.errors.CommunicationError:
                self._successor = self
                self._predecessor = None
                print("Rejoining")
                print(self.joinRing(self._ip, self._port))
            except Exception as e:
                print("Error in stabilize")

#Update the node's predecessor
    def notify(self, chord):
        if self._predecessor == None:
            self._predecessor = chord
        else:
            if self.inInterval("Close", chord.guid, self._predecessor.guid, self._guid):
                self._predecessor = chord

#update a node's finger to find the next few chords in the ring
    def fixFinger(self):
        self.nextFinger = (self.nextFinger + 1)
        if self.nextFinger > self.M:
            self.nextFinger = 1
        nextGuid = self._guid + (1 << (self.nextFinger-1))
        self.finger[self.nextFinger] = self.locateSuccessor(nextGuid)

#Make sure the node is alive, a communication standard
    def isAlive(self):
        return True

#Check if the predecessor is alive    
    def checkPredecessor(self):
        try:
            if self._predecessor != None:
                if not self._predecessor.isAlive():
                    self._predecessor = None
        except:
            self._predecessor = None

#Have the chord check if the guid belong in the interval of begin and end
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

#Debugging purposes: Print all the finger of the node
    def printFinger(self):
        for i in self.finger:
            if i == None:
                print("None")
            else:
                print(i.guid)

#Check to make sure the succeeding node is within the current node and the given guid
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

#Recursivly check to make sure the guid belong in the node, if not pass it onto the next node
    def locateSuccessor(self, guid, debug = False):
        if debug:
            Logger.log("Locating Chord: " + str(self.guid) + " guid: " + str(guid))
        try:
            if guid == self._guid:
                print ("Error it's the same chord")
            else:
                if self._successor.guid != guid:
                    if debug:
                        Logger.log("Current Chord: " + str(self.guid) + " guid: " + str(guid) + " successor Chord: " + str(self._successor.guid))
                    if self.inInterval("Close", guid, self._guid, self._successor.guid):
                        if debug:
                            Logger.log("Success Chord: " + str(self.guid) + " guid: " + str(guid))
                        return self
                    else:
                        nextSuccessor = self.closestPrecedingChord(guid)
                        if debug:
                            Logger.log("Next Successor: " + str(nextSuccessor.guid) + " guid: " + str(guid))
                        return nextSuccessor.locateSuccessor(guid, True)
                else:
                    print("Error, same guid")
        except Exception as e:
            print(str(e))

#Go around the entire ring
    def ringAround(self, initial, count):
        if self.guid == self._successor.guid:
            return 1
        if self.guid != initial.guid:
            return self._successor.ringAround(initial, count+1)
        else:
            return count
        
#Create a new metadata component of the file
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

#Create a new thread to encrypt the portion of data
    def chainEncrypt(self, fileName, data, count, chainEncryption, page, token, prevKey = None):
        encryptThread = encryptingProcess(self, fileName, data, count, chainEncryption, page, token, prevKey)
        encryptThread.start()
        encryptThread.join()
        self.encryptionIndex.append(encryptThread)

#Decrypt a file accordingly to the metadata
    def chainDecrypt(self, fileName, data, pageGet, count, RSAInfo, page = False):
        for x in RSAInfo:
            if x['Set'] == count:
                RSACipher = x["RSACipher"]
                IV = x["IV"]
                tag = x["Tag"]
                m = hashlib.md5()
                m.update((fileName + ":" + str(pageGet) + ":" + str(count-1)).encode('utf-8'))
                grabChord = self.locateSuccessor(int(m.hexdigest(), 16))
                break
        if count == constant.MAX_CHAIN_ENCRYPTION:
#            Logger.printLog("Begin Decryption count == 3")
            newData = Decryptor.chainInitialize(b64decode(RSACipher), b64decode(data), b64decode(IV), b64decode(tag), None)
            return grabChord.chainDecrypt(fileName, newData, pageGet, count-1, RSAInfo, None)
        else:
            if count == 0:
#                print("Count == 0")
                return Decryptor.chainInitialize(b64decode(RSACipher), b64decode(data), b64decode(IV), b64decode(tag), None)
            else:
#                print("Count == str(count)")
                newData = Decryptor.chainInitialize(b64decode(RSACipher), b64decode(data), b64decode(IV), b64decode(tag), None)
                if count-1 == 0:
                    return newData
                else:
                    return grabChord.chainDecrypt(fileName, newData, pageGet, count - 1, RSAInfo, None)

#find the right node that has the guid of the file and read the data and initialize the decrypt
    def download(self, fileName, guidGet, pageGet, RSAInfo):
        getChord = self.locateSuccessor(int(guidGet))
        data = getChord.readData(guidGet)
        return getChord.chainDecrypt(fileName, data, pageGet, 3, RSAInfo, True)

#Open the guid and read the byte
    def readData(self, guidGet):
        fileReader = open(str(self._guid) + "/repository/" + str(guidGet), 'rb')
        return b64encode(fileReader.read()).decode('UTF-8')

#initialize the chain enceryption and upload procedure
    def upload(self, fileName, message, totalPage, token, chordPriv):
        chainEncryption = []
        self.chainEncrypt(fileName, message, 1, chainEncryption, totalPage, token, chordPriv)
        m = hashlib.md5()
        m.update((fileName + ":" + str(totalPage) + ":3").encode('utf-8'))
        return(str(int(m.hexdigest(), 16)))

#Create a new page for a file in the metadata
    def createPage(self, getMessage, getGuid, getToken, getRSAInfo):
        tempMetaData = self.readMetaData()
        f = open(str(self._guid) + "/repository/" + str(getGuid), 'wb+')
        f.write(b64decode(getMessage))
        f.close()
        newData = {}
        newData[getToken] = getRSAInfo
        tempMetaData.append(newData)
        self.writeMetaData(tempMetaData)
        print(str(getGuid) + " has been created")

#Remove page 
    def removePage(self, guidGet):
        filePath = str(self._guid) + "/repository/" + str(guidGet)
        os.remove(filePath)

#Display all file            
    def ls(self):
        metadata = self.readMetaData()
        array = []
        for x in metadata:
            array.append("%s  |  %s  |  %s" %(x['File Name'], x['File Size'], x['Total Pages']))
        return array

#Calculate the size of each page
    def calculateSize(self, getSize):
##        if getSize < constant.:
##            return getSize
##        else
##            return 2**self.findBinary(getSize, 0)
        cutSize = getSize / (self.ringAround(self._successor, 0)*5)
        return 2**self.findBinary(cutSize, 0)
#        return 2**self.findBinary(cutSize, 0)

#Try to make the page size as close to the base of 2 as much as possible
    def findBinary(self, getSize, count):
        if getSize < 2:
            return count
        else:
            return self.findBinary(getSize/2, count+1)

#Check the status of the status of the server
    def getServerStatus(self):
        return self.active

#Shut down the server
    def shutDown(self, master):
        self.active = 0
        if self != master:
            self._successor.shutDown(master)

#Exchange token for completed pages
    def sync(self, token):
        metaData = self.readMetaData()
        for x in metaData:
            for tokenGrab, RSAInfo in x.items():
                if tokenGrab == token:
                    metaData.remove(x)
                    self.writeMetaData(metaData)
                    return RSAInfo

#Thread that allow the encryption of multiple partition of a file.
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
#            Logger.log("Encrypting focus : page = " + str(self.page) + " count = " + str(self.count) + " guid = " + str(int(m.hexdigest(), 16)))
            m = hashlib.md5()
            m.update((self.fileName + ":" + str(self.page) + ":" + str(self.count)).encode('utf-8'))
            getChord = self.chord.locateSuccessor(int(m.hexdigest(), 16), True)
            #Check to make sure the file guid is located in the respective node.
            if getChord.guid == self.chord.guid:
#                Logger.printLog("Encrypt page = " + str(self.page) + " count = " + str(self.count) + " guid = " + str(int(m.hexdigest(), 16)))
                #No need for chain encryption if count is a total of 1, if it's greater then it'll do a chain encryption
                if self.count == 1:
#                   Logger.log("page = " + str(self.page) + " count = initial")
                    RSACipher, cipherText, IV, tag = Encryptor.initialize(self.data)
                else:
#                    Logger.log("page = " + str(self.page) + " count =" + str(count))
                    for y in self.chord.keychain:
                        if y["Chord"] == self.prevKey:
                            for x in self.chainEncryption:
                                if x["Set"] == self.count-1:
                                    RSACipher, cipherText, IV, tag = Encryptor.chainInitialize(b64decode(x["RSACipher"]), b64decode(self.data), b64decode(x["IV"]), b64decode(x["Tag"]), y["Key"])
                self.chainEncryption.append({'Set': self.count, 'RSACipher': RSACipher, 'IV': IV, 'Tag': tag})
                #If the encryption happens the MAX_CHAIN_ENCRPYTION amount of times, then it will be finished, else it will chainEncrpyt again
                if self.count == constant.MAX_CHAIN_ENCRYPTION:                        
                    tokenHash = hashlib.md5()
                    combo = str(int(m.hexdigest(), 16)) + ":" + str(self.token)
                    tokenHash.update(combo.encode('utf-8'))
                    getChord.createPage(cipherText, int(int(m.hexdigest(), 16)), int(tokenHash.hexdigest(), 16), self.chainEncryption)
                else:
                    getChord.chainEncrypt(self.fileName, cipherText, self.count + 1, self.chainEncryption, self.page, self.token, self.chord._guid)
            else:
                getChord.chainEncrypt(self.fileName, self.data, self.count, self.chainEncryption, self.page, self.token, self.prevKey)
        except Exception as e:
            print(str(e))

#start the main thread, this will allow the node to stablize, fix it's finger and check it's predecessor.        
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
