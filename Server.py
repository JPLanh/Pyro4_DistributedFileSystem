import Pyro4
import urllib.request
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
import signal
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class start_server(threading.Thread):
    def __init__(self, chord, ip):
        threading.Thread.__init__(self)
        self._chord = chord
        self.ip = ip

    def run(self):
        try:
            with Pyro4.Daemon(host=str(self.ip), port = int(constant.SERVER_PORT)) as daemon:
                chordURI = daemon.register(self._chord)
                directory = os.path.dirname(str(self._chord.guid)+"/repository/")
                if not os.path.exists(directory):
                    os.makedirs(directory)
                with Pyro4.locateNS(host="35.212.249.77", port= int(constant.SERVER_PORT)) as ns:
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
        except Exception as e:
            print("Unable to start the server")

def signal_handler(signal, frame):
    with Pyro4.locateNS(host="35.212.249.77", port= int(constant.SERVER_PORT)) as ns:
        print(chord.guid)
        ns.remove(str(chord.guid))
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    external_ip = urllib.request.urlopen('https://ident.me').read().decode('utf8')
    amazon_IP = "ec2-" + external_ip.replace('.', '-') + ".us-east-2.compute.amazonaws.com"
    m = hashlib.md5()
    IPGet = str(amazon_IP) + ":" + str(constant.SERVER_PORT)
    m.update(IPGet.encode('UTF-8'))
    guid = int(m.hexdigest(), 16)
    chord = Chord(str(amazon_IP), int(constant.SERVER_PORT), guid)
    try:
        node = start_server(chord, amazon_IP)
        node.start()
        time.sleep(2)

        print(chord.joinRing(amazon_IP, constant.SERVER_PORT))

        if os.path.isfile("Logger.txt"):
            os.remove("Logger.txt")
        f = open("Logger.txt", 'w+')
        f.close()
        
        metaDataGuid = hashlib.md5()
        metaDataGuid.update("metaData".encode('utf-8'))
        if not os.path.isfile(str(guid) + "/repository/" + str(int(metaDataGuid.hexdigest(), 16))):
            metaDataTemp = []
            metaReader = open(str(guid) + "/repository/" + str(int(metaDataGuid.hexdigest(), 16)), 'w+')
            json.dump(metaDataTemp, metaReader)
            metaReader.close()
        
        print("Finish Joining")
    except Exception as e:
        print(e)
