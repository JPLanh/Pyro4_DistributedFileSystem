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
from datetime import datetime
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
        for i in range(0, self.M+1):
            self.finger.append(None)
        print("Loging in as %s:%s" %(ip, port))
        print("Guid: %s" %(guid))
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
    def chord(self):
        return self._chord

    @property
    def successor(self):
        return self._successor

    @property
    def predecessor(self):
        return self._predecessor

    def joinRing(self, getIp, getPort, guid):
        with Pyro4.locateNS(host=getIp, port=int(getPort)-1) as ns:
            for guidGet, guidURI in ns.list(prefix=str(guid)).items():
                chordGet = Pyro4.Proxy(guidURI)
                self._predecessor = None
                self._successor = chordGet.locateSuccessor(self._guid)
                return ("Connected to %s:%s (%s)" %(self._successor.ip, self._successor.port, chordGet.guid))

    def stabilize(self):
        if self._successor != None:
            try:
                x = self._successor.predecessor
                if x != None and x.guid != self._guid and self.inInterval("Close", x.guid, self._guid, self._successor.guid):
                    self._successor = x
                if self._successor.guid != self._guid:
#                    print("%s, %s" %(self._successor.guid, self._guid))
                    self._successor.notify(self)
            except:
                x = self
                self._successor = x
            
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
                print(self._predecessor.guid)
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
        if guid != self._guid:
            i = self.M - 1;
            while i >= 0:
                if self.inInterval("Open", self.finger[i].guid, self._guid, guid):
                    if self.finger[i].guid != guid:
                        return self.finger[i]
            return self._successor

    def simplePrint(self):
        if self.predecessor != None:
            return ("S: %s C: %s P: %s" %(self._successor.guid, self.guid, self._predecessor.guid))
        else:
            return ("S: %s C: %s P: %s" %(self._successor.guid, self.guid, self._predecessor))
            
    def locateSuccessor(self, guid):
        if guid == self._guid:
            print ("Error it's the same shit")
        else:
            if self._successor.guid != guid:
                if self.inInterval("Close", guid, self._guid, self._successor.guid):
                    return self._successor
                else:
                    nextSuccessor = self.closestPrecedingChord(guid)
                    return nextSuccessor.locateSuccessor(guid)

    def readMetaData(self):
        m = hashlib.md5()
        m.update("MetaData".encode('utf-8'))
        meta = int(m.hexdigest(), 16)
        #jread = open(str(self.locateSuccessor(meta).guid) + "/repository/"+str(meta), 'r')
        jread = open(constant.USB_DIR+str(meta), 'r')
        jsonRead = json.load(jread)
        return jsonRead["metadata"]

    def writeMetaData(self, rawData):
        m = hashlib.md5()
        m.update("MetaData".encode('utf-8'))
        meta = int(m.hexdigest(), 16)
        #f = open(str(self.locateSuccessor(meta).guid) + "/repository/"+str(meta), 'w')
        f = open(constant.USB_DIR+str(meta), 'w')
        metadata = {}
        metadata['metadata'] = rawData
        json.dump(metadata, f)
        f.close()

    def ringAround(self, initial, count):
        print("ping ring: %s (%s)" %(count, self.guid))
        if self.guid != initial.guid:
            return self._successor.ringAround(initial, count+1)
        elif self.guid != self._successor:
            return 1
        else:
            return count            
        
    def newFile(self, file):
        metadata = self.readMetaData()
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
        metadata.append(fileInfo)
        self.writeMetaData(metadata)

    def distribute(self, file):
        metadata = self.readMetaData()
        for x in metadata:
            if x['File Name'] == file:
                f = open(file, 'rb')
                data = f.read()
                pageSize = self.calculateSize(len(data))
                byteRead = x['File Size']
                count = 0
                while byteRead < len(data):
                    chainEncryption = {}
                    if (len(data)-byteRead) > pageSize:
                        self.chainEncrypt(data[byteRead:(byteRead+pageSize)], 0, chainEncryption)
                    else:
                        self.chainEncrypt(data[byteRead:len(data)], 0, chainEncryption)

    def chainEncrypt(self, data, count, chainEncrpytion):
        if count == constant.MAX_CHAIN_ENCRYPTION:
            return chainEncryption
        elif count == 0:
            chainEncryption["RSACipher"], chainEncryption["cipherText"], chainEncryption["IV"], chainEncryption["tag"] = Encryptor.initialize(data)
            return self.chainEncrypt(chainEncryption["cipherText"], count+1, chainEncryption)
        else:
            chainEncryption["RSACipher"], chainEncryption["cipherText"], chainEncryption["IV"], chainEncryption["tag"] = Encryptor.chainInitialize(chainEncryption["RSACipher"], chainEncryption["cipherText"], chainEncryption["IV"], chainEncryption["tag"], count)
            return self.chainEncrypt(chainEncryption["cipherText"], count+1, chainEncryption)

    def appendTwo(self, file):
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
                newPage["Guid"] = int(m.hexdigest(), 16)
                chordGet = self.locateSuccessor(newPage["Guid"])
                if (len(data)-byteRead) > x['Page Size']:
                  self.logger("Encrypt 1")
                  RSACipher, cipherText, IV, tag = Encryptor.initialize(data[byteRead:(byteRead+x['Page Size'])])
                  newPage["Size"] = x['Page Size']
                  x['File Size'] += x['Page Size']
                else:
                  self.logger("Encrypt 1")
                  RSACipher, cipherText, IV, tag = Encryptor.initialize(data[byteRead:len(data)])
                  newPage["Size"] = len(data)-byteRead
                  x['File Size'] += len(data)-byteRead
                newPage["RSACipher"] = b64encode(RSACipher).decode('utf-8')
                newPage["IV"] = b64encode(IV).decode('utf-8')
                newPage["Tag"] = b64encode(tag).decode('utf-8')
                chordGet.createPage(b64encode(cipherText).decode('utf-8'), newPage["Guid"])
                loggerThing = "Count: " + str(x['Total Pages']) + " byte: " + str(x['File Size'])
                self.logger(loggerThing)
                x['Pages'].append(newPage)                   
                self.writeMetaData(metadata)
                return round((byteRead / len(data)) * 100)                

        
    def append(self, file):
        metadata = self.readMetaData()
        for x in metadata:
            if x['File Name'] == file:
                f = open(file, 'rb')
                data = f.read()
                pageSize = self.calculateSize(len(data))
                byteRead = x['File Size']
                count = 0
                while byteRead < len(data):
                    x['Total Pages'] += 1
                    newPage = {}
                    m = hashlib.md5()
                    IPGet = file + ":" + str(count)
                    m.update(IPGet.encode('utf-8'))
                    newPage["Page"] = count
                    newPage["Guid"] = int(m.hexdigest(), 16)
                    chordGet = self.locateSuccessor(newPage["Guid"])
                    if (len(data)-byteRead) > pageSize:
                      self.logger("Encrypt 1")
                      RSACipher, cipherText, IV, tag = Encryptor.initialize(data[byteRead:(byteRead+pageSize)])
                      newPage["Size"] = pageSize
                      byteRead += pageSize
                      x['File Size'] += pageSize
                    else:
                      self.logger("Encrypt 1")
                      RSACipher, cipherText, IV, tag = Encryptor.initialize(data[byteRead:len(data)])
                      newPage["Size"] = len(data)-byteRead
                      byteRead += len(data)-byteRead
                      x['File Size'] += len(data)-byteRead
                    newPage["RSACipher"] = b64encode(RSACipher).decode('utf-8')
                    newPage["IV"] = b64encode(IV).decode('utf-8')
                    newPage["Tag"] = b64encode(tag).decode('utf-8')
                    chordGet.createPage(b64encode(cipherText).decode('utf-8'), newPage["Guid"])
                    x['Pages'].append(newPage)
                    count = count + 1                    
                self.writeMetaData(metadata)
                break
            
    def createPage(self, getMessage, getGuid):
        f = open(str(self._guid) + "\\repository\\" + str(getGuid), 'wb+')
        f.write(b64decode(getMessage))
        f.close()
 
    def removePage(self, getGuid):
        os.remove(self._guid +"\\repository\\" + getGuid)

    def delete(self, file):
        metadata = self.readMetaData()
        for x in metadata:
            if x['File Name'] == file:
                for y in x['Pages']:
                    chordGet = self.locateSuccessor(y['Guid'])
                    chordGet.removePage(y['Guid'])
#                    os.remove(str(self.locateSuccessor(y['Guid']).guid) + "\\repository\\" + str(y['Guid']))
                metadata.remove(x)
                self.writeMetaData(metadata)
                break;

    def ls(self):
        metadata = self.readMetaData()
        array = []
        for x in metadata:
            array.append("%s  |  %s  |  %s" %(x['File Name'], x['File Size'], x['Total Pages']))
        return array

    def download(self, file):
        metadata = self.readMetaData()
        for x in metadata:
            if x['File Name'] == file:
                if not os.path.exists("./Download"):
                    os.makedirs("./Download")
                f = open("./Download/"+file, 'wb')
                for y in x['Pages']:
                    tempF = open(str(self.locateSuccessor(y['Guid']).guid) + "\\repository\\" + str(y['Guid']), 'rb')
                    f.write(Decryptor.initialize(b64decode(y['RSACipher']), tempF.read(), b64decode(y['IV']), b64decode(y['Tag'])))
#                    f.write(tempF.read())
                    tempF.close()
                f.close()
                    
        
    def calculateSize(self, getSize):
        cutSize = getSize / (self.ringAround(self._successor, 0)*5)
        return 2**self.findBinary(cutSize, 0)

    def findBinary(self, getSize, count):
        if getSize < 2:
            return count
        else:
            return self.findBinary(getSize/2, count+1)

    def logger(self, data):
        try:
            f = open("Logger.txt", 'a+')
        except:
            f = open("Logger.txt", 'w+')
        f.write("[" + str(datetime.now()) + "] " + data + "\n")
        f.close()

class looping(threading.Thread):
    def __init__(self, chord):
        threading.Thread.__init__(self)
        self.chord = chord

    def run(self):
        while True:
        #    print("before stab: %s" %self.chord.successor)
            self.chord.stabilize()
         #   print("after stab: %s" %self.chord.successor)
            self.chord.fixFinger()
            self.chord.checkPredecessor()
            time.sleep(2)
