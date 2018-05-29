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

    def newFile(self, file):
        jread = open(self._guid + "/repository/metadata", 'r')
        jsonRead = json.load(jread)
        metadata = jsonRead["metadata"]
        print(metadata)
        
    def add(self, item):
        self.list.append(item)

    def remove(self, item):
        self.list.remove(item)
