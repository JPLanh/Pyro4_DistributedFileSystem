import Pyro4
from Pyro4 import naming
import hashlib
import os
import threading
import time
import json
from Chord import Chord

class start_name_server(threading.Thread):
    def __init__(self):
      threading.Thread.__init__(self)

    def run(self):
      Pyro4.naming.startNSloop()
      
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
          if not os.path.exists(directory):
            os.makedirs(directory)
          try:
            f = open(directory+"/metadata", 'r')
          except:
            createMeta(directory)
          with Pyro4.locateNS() as ns:
            ns.register(str(self._chord.guid), chordURI)
          print("Thread started")
          daemon.requestLoop()

def createMeta(path):
  print("File was not found")
  metaData = {}
  fileList = []
  metaData["metadata"] = fileList  
  f = open(path+"/metadata", 'w')
  json.dump(metaData, f)
  f.close()
  
def prompt(chord):
    print("\n\n")
    print('{:#^50}'.format(""))           
    print('{:^50}'.format("Distributed File System"))            
    print('{:#^50}'.format(""))
    getChoice = input("('help' for commands):")
    choiceSplit = getChoice.split(" ")

    if len(choiceSplit) == 1:
        if choiceSplit[0].lower() == "help":
            print('\nAction \t\t Command   Argument \t Description')
            print('{:#^50}'.format(""))
            print('List Files \t ls    \t  \t\t List all files')
            print('Upload \t\t up \t  {filename} \t Upload the specifed filename')
            print('Download \t down \t  {filename} \t Download the specifed filename')
            print('Exit \t\t exit \t \t\t Exit from the system')
        elif choiceSplit[0].lower() == "ls":
          chord.simplePrint()
        elif choiceSplit[0].lower() == "ring":
          chord.successor.ringAround(chord, 0)
    elif len(choiceSplit) > 1:
        if choiceSplit[0].lower() == "up":
            fileName = getChoice[3:]
            chord.newFile(fileName)
        elif choiceSplit[0].lower() == "join":
            m = hashlib.md5()
            IPGet = choiceSplit[1] + ":" + str(choiceSplit[2])
            m.update(IPGet.encode('utf-8'))  
            chord.joinRing(int(m.hexdigest(), 16))
    
if __name__ == "__main__":
#    nameServer = start_name_server()
#    nameServer.start()
    getIP = input("IP:")
    getPort = int(input("Port:"))
#    getIP = 'localhost'
#    getPort = 23245
    #try:
    m = hashlib.md5()
    IPGet = getIP + ":" + str(getPort)
    m.update(IPGet.encode('utf-8'))
    guid = int(m.hexdigest(), 16)
    chord = Chord(getIP, getPort, guid)
    node = start_server(getIP, getPort, chord)
    node.start()
    time.sleep(10)
    print("Welcome User!")
    while True:
         prompt(chord)

