import Pyro4
from Pyro4 import naming
import hashlib
import os
import threading
import time
import json
from Chord import Chord

class start_server(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        print("Thread started")
        Pyro4.naming.startNSloop()

def createMeta(path):
  print("File was not found")
  metaData = {}
  metaData["metadata"] = None
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
#        elif choiceSplit[0].lower() == "ls":
    elif len(choiceSplit) == 2:
      if choiceSplit[0].lower() == "up":
        chord.newFile("Test")
        
        
if __name__ == "__main__":
    getIP = input("IP:")
    getPort = int(input("Port:"))
    #try:
    thread1 = start_server()
    thread1.start()
    with Pyro4.Daemon(host=getIP, port = getPort) as daemon:
        with Pyro4.locateNS() as ns:
            m = hashlib.md5()
            IPGet = getIP + ":" + str(getPort)
            m.update(IPGet.encode('utf-8'))  
            chord = Chord(getIP, getPort, m.hexdigest())
            chordURI = daemon.register(chord)          
            directory = os.path.dirname(str(m.hexdigest())+"/repository/")
            if not os.path.exists(directory):
              os.makedirs(directory)
            try:
              f = open(directory+"/metadata", 'r')
            except:
              createMeta(directory)
            ns.register(str(m.hexdigest()), chordURI)
            print("Welcome User!")
    while True:
        prompt(chord)
    #except:
    #    print("Unable to start thread")

##    with Pyro4.locateNS() as ns:
##        print(ns.list())
