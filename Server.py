import Pyro4
from Pyro4 import naming
import hashlib
import os
import ctypes
import threading
import time
import json
import constant
import subprocess
from Chord import Chord
import Client

class start_name_server(threading.Thread):
    def __init__(self, IP, port):
      threading.Thread.__init__(self)
      self._ip = IP
      self._port = port-1

    def run(self):
      Pyro4.naming.startNSloop(host=self._ip, port=self._port)
      
class start_server(threading.Thread):
    def __init__(self, ip, port, chord):
        threading.Thread.__init__(self)
        self._ip = ip
        self._port = port
        self._chord = chord

    def run(self):
      with Pyro4.Daemon(host=self._ip, port = self._port) as daemon:
          chordURI = daemon.register(self._chord)
          directory = os.path.dirname(str(self._chord.guid)+"/repository/")
          m = hashlib.md5()
          m.update("MetaData".encode('utf-8'))
          if not os.path.exists(directory):
            os.makedirs(directory)
          with Pyro4.locateNS(host=self._ip, port= self._port-1) as ns:
            ns.register(str(self._chord.guid), chordURI)
          print("Chord connected as: %s:%s" %(self._ip, self._port))
          daemon.requestLoop()
            
if __name__ == "__main__":
    getIP = input("IP:")
    getPort = int(input("Port:"))
    #try:
    m = hashlib.md5()
    IPGet = getIP + ":" + str(getPort)
    m.update(IPGet.encode('utf-8'))
    guid = int(m.hexdigest(), 16)
    ctypes.windll.kernel32.SetConsoleTitleW(getIP +":"+ str(getPort) + " (" + str(guid) + ")")
    chord = Chord(getIP, getPort, guid, True)

    nameServer = start_name_server(getIP, getPort)
    nameServer.start()

    node = start_server(getIP, getPort, chord)
    node.start()
    time.sleep(2)
    print("Server has been started")

    subprocess.call(['python', 'Client.py', str(getIP), str(getPort)])
    while True:
        pass
