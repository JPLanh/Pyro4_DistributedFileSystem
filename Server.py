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
import sys
import Logger
from Chord import Chord
import Client
from base64 import b64decode
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
          Logger.log("Server: Flag 1")
          if not os.path.exists(directory):
            os.makedirs(directory)
          Logger.log("Server: Flag 2")
          with Pyro4.locateNS(host=self._ip, port= self._port-1) as ns:
            ns.register(str(self._chord.guid), chordURI)
          Logger.log("Server: Flag 3")
          if not os.path.isfile(constant.CHORD_PRIV_PEM):
              if not os.path.isfile(constant.CHORD_PUB_PEM):
                  Logger.log("Server: Flag 4")
                  privKey, pubKey = self._chord.createKeys()
                  f = open(constant.CHORD_PRIV_PEM, 'wb+')
##                  try:
                  f.write(b64decode(privKey))
##                  except Exception as e:
##                      Logger.log(str(e))
                  f.close()                  
                  f = open(constant.CHORD_PUB_PEM, 'wb+')
                  f.write(b64decode(pubKey))
                  f.close()
#                  os.rename(constant.TEMP_PRIV_PEM, constant.CHORD_PRIV_PEM)
#                  os.rename(constant.TEMP_PUB_PEM, constant.CHORD_PUB_PEM)
                  Logger.log("Server: Flag 7")                  
          Logger.log("Server: Flag 8")
              
          daemon.requestLoop()
            
if __name__ == "__main__":
    m = hashlib.md5()
    IPGet = sys.argv[1] + ":" + sys.argv[2]
    m.update(IPGet.encode('utf-8'))
    guid = int(m.hexdigest(), 16)
    chord = Chord(sys.argv[1], sys.argv[2], guid)
    ctypes.windll.kernel32.SetConsoleTitleW(sys.argv[1] +":"+ sys.argv[2] + " (" + str(guid) + ")")

    try:
        Pyro4.locateNS(host=sys.argv[1], port =int(sys.argv[2]))
    except:
        nameServer = start_name_server(sys.argv[1], int(sys.argv[2]))
        
    nameServer.start()
    time.sleep(2)

    node = start_server(sys.argv[1], int(sys.argv[2]), chord)
    node.start()

    while True:
        pass
