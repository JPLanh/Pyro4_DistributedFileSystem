import Pyro4
from Pyro4 import naming
import hashlib
import ctypes
import os
import json
import threading
import time

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

    def stabilize(self):
        try:
            if self._successor != None:
                x = self._successor.predecessor
                if x != None and x.guid != self._guid and self.inInterval("Open", x.guid, self._guid, self._successor.guid):
                    self._successor = x
               # if self._successor.guid != self._guid:
                self._successor.notify(self)
        except:
            print("error in stabilize")
            
    def notify(self, chord):
        try:            
            if self._predecessor == None or (self._predecessor != None and self.inInterval("Open", chord.guid, self._predecessor.guid, self._guid)):
                self._predecessor = chord
        except:
            print("error in notify")
            
    def fixFinger(self):
        self.nextFinger = (self.nextFinger + 1)
        if self.nextFinger > self.M:
            self.nextFinger = 1
        nextGuid = self._guid + (1 << (self.nextFinger-1))
        self.finger[self.nextFinger] = self.locateSuccessor(nextGuid)
    
    def isAlive(self):
        return True
    
    def checkPredecessor(self):
        if self._predecessor != None and not self._predecessor.isAlive():
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
            print("S: %s C: %s P: %s" %(self._successor.guid, self.guid, self._predecessor.guid))
        else:
            print("S: %s C: %s P: %s" %(self._successor.guid, self.guid, self._predecessor))
            
    def locateSuccessor(self, guid):
        if guid == self._guid:
            print("Error it's the same shit")
        else:
            if self._successor.guid != guid:
                if self.inInterval("Close", guid, self._guid, self._successor.guid):
                    return self._successor
                else:
                    nextSuccessor = self.closestPrecedingChord(guid)
                    return nextSuccessor.locateSuccessor(guid)
                
    def joinRing(self, guid):
        with Pyro4.locateNS() as ns:
            print("Joining Ring")
            for guidGet, guidURI in ns.list(prefix=str(guid)).items():
                chordGet = Pyro4.Proxy(guidURI)
                self._predecessor = None
                self._successor = chordGet.locateSuccessor(self._guid)
                print("Connected to %s:%s" %(self._successor.ip, self._successor.port))

    def readMetaData(self):
        m = hashlib.md5()
        m.update("MetaData".encode('utf-8'))
        meta = int(m.hexdigest(), 16)
        jread = open(str(self.locateSuccessor(meta).guid) + "/repository/"+str(meta), 'r')
        jsonRead = json.load(jread)
        return jsonRead["metadata"]

    def writeMetaData(self, rawData):
        m = hashlib.md5()
        m.update("MetaData".encode('utf-8'))
        meta = int(m.hexdigest(), 16)
        f = open(str(self.locateSuccessor(meta).guid) + "/repository/"+str(meta), 'w')
        metadata = {}
        metadata['metadata'] = rawData
        json.dump(metadata, f)
        f.close()

    def ringAround(self, initial, count):
        if self.guid != initial.guid:
            return self._successor.ringAround(initial, count+1)
        else:
            return count            
        
    def newFile(self, file):
        metadata = self.readMetaData()
        fileInfo = {}
        fileInfo['File Name'] = file
        fileInfo['Total Pages'] = 0
        fileInfo['Page Size'] = 0
        fileInfo['File Size'] = 0
        pages = []
        fileInfo['Pages'] = pages
        metadata.append(fileInfo)
        self.writeMetaData(metadata)

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
                    chordGet = self.locateSuccessor(int(m.hexdigest(), 16))
                    newF = open(str(chordGet.guid) + "\\repository\\" + str(int(m.hexdigest(), 16)), 'wb')
                    if (len(data)-byteRead) > pageSize:      
                      newF.write(data[byteRead:(byteRead+pageSize)])
                      byteRead += pageSize
                      newPage["Size"] = pageSize
                      x['File Size'] += pageSize
                    else:
                      newF.write(data[byteRead:len(data)])
                      newPage["Size"] = len(data)-byteRead
                      byteRead += len(data)-byteRead
                      x['File Size'] += len(data)-byteRead
                    x['Pages'].append(newPage)
                    count = count + 1
                    newF.close()
                self.writeMetaData(metadata)
                break                
        
    def delete(self, file):
        metadata = self.readMetaData()
        for x in metadata:
            print("%s, %s" %(x['File Name'], file))
            if x['File Name'] == file:
                for y in x['Pages']:
                    os.remove(str(self.locateSuccessor(y['Guid']).guid) + "\\repository\\" + str(y['Guid']))
                metadata.remove(x)
                self.writeMetaData(metadata)
                break;

    def ls(self):
        metadata = self.readMetaData()
        for x in metadata:
            print("%s  |  %s  |  %s" %(x['File Name'], x['File Size'], x['Total Pages']))

    def download(self, file):
        metadata = self.readMetaData()
        for x in metadata:
            if x['File Name'] == file:
                f = open("Download\\"+file, 'wb')
                for y in x['Pages']:
                    tempF = open(str(self.locateSuccessor(y['Guid']).guid) + "\\repository\\" + str(y['Guid']), 'rb')
                    f.write(tempF.read())
                    tempF.close()
                f.close()
                    
        
    def calculateSize(self, getSize):
        cutSize = getSize / (self.ringAround(self._successor, 0)*5)
        print(cutSize)
        return 2**self.findBinary(cutSize, 0)

    def findBinary(self, getSize, count):
        if getSize < 2:
            return count
        else:
            return self.findBinary(getSize/2, count+1)
        
        
    def add(self, item):
        self.list.append(item)

    def remove(self, item):
        self.list.remove(item)

class looping(threading.Thread):
    def __init__(self, chord):
        threading.Thread.__init__(self)
        self.chord = chord

    def run(self):
        while True:
            self.chord.stabilize()
            self.chord.fixFinger()
            self.chord.checkPredecessor()
            time.sleep(5)
