import Pyro4
from Pyro4 import naming
import hashlib
import os
import time
import constant
import sys
import Logger
import threading
import json
from Chord import Chord
from base64 import b64decode, b64encode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class start_name_server(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        Pyro4.naming.startNSloop(host=str(constant.SERVER_IP), port=int(constant.SERVER_PORT)-1)

class start_server(threading.Thread):
    def __init__(self, chord):
        threading.Thread.__init__(self)
        self._chord = chord

    def run(self):
        with Pyro4.Daemon(host=str(constant.SERVER_IP), port = int(constant.SERVER_PORT)) as daemon:
            chordURI = daemon.register(self._chord)
            directory = os.path.dirname(str(self._chord.guid)+"/repository/")
            if not os.path.exists(directory):
                os.makedirs(directory)
            with Pyro4.locateNS(host=str(constant.SERVER_IP), port= int(constant.SERVER_PORT)-1) as ns:
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
    IPGet = str(constant.SERVER_IP) + ":" + str(constant.SERVER_PORT)
    m.update(IPGet.encode('UTF-8'))
    guid = int(m.hexdigest(), 16)
    chord = Chord(str(constant.SERVER_IP), int(constant.SERVER_PORT), guid)

    nameServer = start_name_server()
    nameServer.start()
    time.sleep(2)
    
    node = start_server(chord)
    node.start()
    time.sleep(2)

    serverFile = open("./ServerList", 'r')
    serverList = json.load(serverFile)
    for x in serverList["Servers"]:
        try:
            if x["IP"] != constant.SERVER_IP:
                m = hashlib.md5()
                IPGet = str(x["IP"] + ":" + str(x["Port"]))
                m.update(IPGet.encode('UTF-8'))
                guid = int(m.hexdigest(), 16)
                chord.joinRing(x["IP"], x["Port"], guid)
                print("Joined")
                break
        except:
            print("Unable to join")

    print("Finish Joining")
    while chord.getServerStatus == 1:
        pass
