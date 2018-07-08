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
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import serialization, hashes, hmac, asymmetric, padding
from base64 import b64decode, b64encode

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
          if not os.path.isfile(constant.CHORD_PRIV_PEM):
              if not os.path.isfile(constant.CHORD_PUB_PEM):
                  privKey, pubKey = self._chord.createKeys()
                  f = open(constant.CHORD_PRIV_PEM, 'wb+')
                  f.write(b64decode(privKey))
                  f.close()                  
                  f = open(constant.CHORD_PUB_PEM, 'wb+')
                  f.write(b64decode(pubKey))
                  f.close()

          f = open(constant.CHORD_PRIV_PEM, 'rb')
          private_key = serialization.load_pem_private_key(
              f.read(),
              password=None,
              backend=default_backend()
          )
          f.close()
          privPem = private_key.private_bytes(
              encoding=serialization.Encoding.PEM,
              format=serialization.PrivateFormat.TraditionalOpenSSL,
              encryption_algorithm=serialization.NoEncryption()
          )
          self._chord.addKey(self._chord, b64encode(privPem).decode('UTF-8'))
                              
          daemon.requestLoop()
            
if __name__ == "__main__":
    m = hashlib.md5()
    IPGet = sys.argv[1] + ":" + sys.argv[2]
    m.update(IPGet.encode('utf-8'))
    guid = int(m.hexdigest(), 16)
    chord = Chord(sys.argv[1], sys.argv[2], guid)
    #ctypes.windll.kernel32.SetConsoleTitleW(sys.argv[1] +":"+ sys.argv[2] + " (" + str(guid) + ")")

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
