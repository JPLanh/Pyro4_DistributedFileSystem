import Pyro4
import hashlib
import os

@Pyro4.expose
class Chord(object):
    def __init__(self, ip, port):
        self._ip = ip
        self._port = port
        self.list = []

    @property
    def ip(self):
        return self._ip

    @property
    def port(self):
        return self._port

    def add(self, item):
        self.list.append(item)

    def remove(self, item):
        self.list.remove(item)

if __name__ == "__main__":
    getIP = input("IP:").strip()
    getPort = int(input("Port:").strip())
    chord = Chord(getIP, getPort)
    with Pyro4.Daemon(host=chord.ip, port = chord.port) as daemon:
        chordURI = daemon.register(chord)
        with Pyro4.locateNS() as ns:
            m = hashlib.md5()
            IPGet = chord.ip + ":" + str(chord.port)
            m.update(IPGet.encode('utf-8'))            
            directory = os.path.dirname(str(m.hexdigest())+"/repository")
            if not os.path.exists(directory):
                os.makedirs(directory)
            ns.register(str(m.hexdigest()), chordURI)
            print("chord registered")            
            #daemon.requestLoop()
    print("What would you like to do?")

    with Pyro4.locateNS() as ns:
        print(ns.list())
