import Pyro4
from Pyro4 import naming
import hashlib
import sys
import os
import ctypes
import threading
import time
import json
import constant
import subprocess
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import asymmetric, serialization
from Chord import Chord

def register():
    privateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    privPem = privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    pubKey = privateKey.public_key()
    pubPem = pubKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    if not os.path.exists(constant.USB_DIR):
     os.makedirs(constant.USB_DIR)
     
    privateWrite = open(constant.PRIVATE_PEM, 'wb')
    privateWrite.write(privPem)
    privateWrite.close()
    publicWrite = open(constant.PUBLIC_PEM, 'wb')
    publicWrite.write(pubPem)
    publicWrite.close()

    
    metaData = {}
    fileList = []
    m = hashlib.md5()
    m.update("MetaData".encode('utf-8'))
    metaData["metadata"] = fileList  
    f = open(constant.USB_DIR+str(int(m.hexdigest(), 16)), 'w')
    json.dump(metaData, f)
    f.close()
      
def prompt(chord):
    os.system('cls')
    print('{:#^50}'.format(""))           
    print('{:^50}'.format("Distributed File System"))            
    print('{:#^50}'.format(""))
    getChoice = input("('help' for commands):")
    choiceSplit = getChoice.split(" ")

    if len(choiceSplit) == 1:
        if choiceSplit[0].lower() == "help":
            print('\nAction \t\t Command   Argument \t Description')
            print('{:#^50}'.format(""))
            print('Register \t reg    \t  \t\t Register yourself')
            print('List Files \t ls    \t  \t\t List all files')
            print('Upload \t\t up \t  {filename} \t Upload the specifed filename')
            print('Download \t down \t  {filename} \t Download the specifed filename')
            print('Exit \t\t exit \t \t\t Exit from the system')
        elif choiceSplit[0].lower() == "ls":
          array = chord.ls()
          for x in array:
              print(x)
        elif choiceSplit[0].lower() == "ring":
            chord.successor.ringAround(chord, 0)
        elif choiceSplit[0].lower() == "finger":
            chord.printFinger()
        elif choiceSplit[0].lower() == "sap":
            print(chord.simplePrint())
        elif choiceSplit[0].lower() == "reg":
            register()
    elif len(choiceSplit) > 1:
        if choiceSplit[0].lower() == "up":
            fileName = getChoice[3:]
 #           try:
            File = os.path.isfile(fileName)
            chord.newFile(fileName)
            progress = 0
            count = 0
            while progress < 100:
                os.system('cls')
                print("Uploading, please wait: %s " %progress)
                progress = chord.appendTwo(fileName)
#            chord.append(fileName)
 #           except:
#                print("File does not exist")
        elif choiceSplit[0].lower() == "join":
            m = hashlib.md5()
            IPGet = choiceSplit[1] + ":" + str(choiceSplit[2])
            m.update(IPGet.encode('utf-8'))  
            print(chord.joinRing(choiceSplit[1], str(choiceSplit[2]), int(m.hexdigest(), 16)))
        elif choiceSplit[0].lower() == "del":
            fileName = getChoice[4:]
            chord.delete(fileName)
        elif choiceSplit[0].lower() == "down":
            fileName = getChoice[5:]
            chord.download(fileName)

if __name__ == "__main__":
#    getIP = input("IP:")
#    getPort = int(input("Port:"))
    getIP = "KENGPENG-PC"
    getPort = 23245
    IPGet = getIP + ":" + str(getPort)
    m = hashlib.md5()
    m.update(IPGet.encode('utf-8'))
    guid = int(m.hexdigest(), 16)
#    subprocess.call(['python', 'Server.py', str(getIP), str(getPort)])
    surver = subprocess.Popen(['python', 'Server.py', str(getIP), str(getPort)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#    output, err = surver.communicate()
    print("Sleep")
    time.sleep(5)

    print("finish sleeping")
    with Pyro4.locateNS(host=getIP, port=getPort-1) as ns:
        for guidGet, guidURI in ns.list(prefix=str(guid)).items():
            chord = Pyro4.Proxy(guidURI)
                        
    ctypes.windll.kernel32.SetConsoleTitleW(getIP +":"+ str(getPort) + " (" + str(guid) + ")")
    time.sleep(1)

    
    while True:
         prompt(chord)
         if chord.successor != chord.guid:
             ctypes.windll.kernel32.SetConsoleTitleW(IPGet + "-> " + str(chord.successor.ip) + ":" + str(chord.successor.port))
