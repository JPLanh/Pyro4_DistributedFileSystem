import Pyro4
from Pyro4 import naming
import hashlib
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
        self.successor = self
        self._predecessor = None
        self.finger = []
        self.nextFinger = 0
        for i in range(0, self.M):
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
    def chord(self):
        return self._chord

    @property
    def predecessor(self):
        return self._predecessor

    def stabilize(self):
        if self.successor != None:
            x = self.successor.predecessor
            if x != None and x.guid != self._guid and self.inCloseInterval(x.guid, self._guid, self.successor.guid):
                self.successor = x
           # if self.successor.guid != self._guid:
            self.successor.notify(self)

    def notify(self, chord):
        if self._predecessor == None or (self._predecessor != None and self.inCloseInterval(chord.guid, self._predecessor.guid, self._guid)):
            self._predecessor = chord

    def fixFinger(self):
        nextGuid = self._guid + 1 << (self.nextFinger+1)
        self.finger[self.nextFinger] = self.locateSuccessor(nextGuid)
        self.nextFinger = (self.nextFinger + 1)%self.M
    
    def isAlive(self):
        return True
    
    def checkPredecessor(self):
        if self._predecessor != None and not self._predecessor.isAlive():
            self._predecessor = None

    def inCloseInterval(self, guid, begin, end):
        if begin < end:
            return guid > begin and guid < end
        else:
            return guid > begin or guid < end

    def locateSuccessor(self, guid):
        if guid == self._guid:
            print("Error it's the same shit")
        else:
            if self.successor.guid != guid:
                if self.inCloseInterval(guid, self._guid, self.successor.guid):
                    return self.successor
                nextSuccessor = self.closestPrecedingChord(guid)
                if nextSuccessor == None:
                    return None
                return nextSuccessor.locateSuccessor(guid)

    def printFinger(self):
        for i in self.finger:
            print(i)

    def closestPrecedingChord(self, guid):
        if guid != self._guid:
            i = self.M - 1;
            while i >= 0:
                if self.inCloseInterval(self.finger[i].guid, self._guid, guid):
                    if self.finger[i].guid != guid:
                        return self.finger[i]
            return self.successor

    def simplePrint(self):
        if self.predecessor != None:
            print("S: %s C: %s P: %s" %(self.successor.guid, self.guid, self._predecessor.guid))
        else:
            print("S: %s C: %s P: %s" %(self.successor.guid, self.guid, self._predecessor))
            

    def joinRing(self, guid):
        with Pyro4.locateNS() as ns:
            for guidGet, guidURI in ns.list(prefix=str(guid)).items():
                chordGet = Pyro4.Proxy(guidURI)
                self._predecessor = None
                self.successor = chordGet.locateSuccessor(self._guid)
                print("Joining Ring")                 

    def readMetaData(self):
        jread = open(self._guid + "/repository/metadata", 'r')
        jsonRead = json.load(jread)
        return jsonRead["metadata"]

    def writeMetaData(self, rawData):
        f = open(self._guid + "/repository/metadata", 'w')
        metadata = {}
        metadata['metadata'] = rawData
        json.dump(metadata, f)
        f.close()

    def ringAround(self, initial, count):
        if self.guid != initial.guid:
            print("%i : %s" %(count, initial.guid))
            self.successor.ringAround(initial, count+1)
        else:
            print("%i : %s" %(count, initial.guid))            
        
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
