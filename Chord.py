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
        self._ip = ip
        self._port = port
        self._guid = guid

    @property
    def ip(self):
        return self._ip

    @property
    def port(self):
        return self._port

    @property
    def guid(self):
        return self._guid

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

    def joinRing(self, guid):
        with Pyro4.locateNS() as ns:
            for guidGet, guidURI in ns.list(prefix=guid).items():
                print(Pyro4.Proxy(guidURI))
                
                
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
