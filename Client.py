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
import Logger
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import asymmetric, serialization
from Chord import Chord
from base64 import b64encode, b64decode

def register(chord):
    privKey, pubKey = chord.createKeys()

    if not os.path.exists(constant.USB_DIR):
     os.makedirs(constant.USB_DIR)

    f = open(constant.PRIVATE_PEM, 'wb+')
    f.write(b64decode(privKey))
    f.close()

    f = open(constant.PUBLIC_PEM, 'wb+')
    f.write(b64decode(pubKey))
    f.close()
        
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
        elif choiceSplit[0].lower() == "key":
            chord.keyPrint()
        elif choiceSplit[0].lower() == "ring":
            chord.successor.ringAround(chord, 0)
        elif choiceSplit[0].lower() == "finger":
            chord.printFinger()
        elif choiceSplit[0].lower() == "sap":
            print(chord.simplePrint())
        elif choiceSplit[0].lower() == "reg":
            register(chord)
        elif choiceSplit[0].lower() == "new":
            fileGet = chord.replaceKey()
            for x in fileGet:
                print(x)
    elif len(choiceSplit) > 1:
        if choiceSplit[0].lower() == "up":
            fileName = getChoice[3:]
            try:
                File = os.path.isfile(fileName)
                chord.newFile(fileName)
                progress = 0
                count = 0
                while progress < 100:
                    progress = chord.append(fileName)
                    os.system('cls')
                    if progress == 100:
                        print("Upload completed")
                        break;
                    print("Uploading, please wait: %s " %progress)                    
            except Exception as e:
                print(e)
        elif choiceSplit[0].lower() == "join":
            if len(choiceSplit) == 3:
                if (choiceSplit[1] == chord.ip) and (choiceSplit[2] == chord.port):
                    print("Unable to join the same chord")
                else:
                    try:
                        m = hashlib.md5()
                        IPGet = choiceSplit[1] + ":" + str(choiceSplit[2])
                        m.update(IPGet.encode('utf-8'))
                        try:
                            print(chord.joinRing(choiceSplit[1], str(choiceSplit[2]), int(m.hexdigest(), 16)))
                        except Pyro4.errors.NamingError:
                            print("Unable to locate server")
                    except Exception as e:
                        print(str(e))
            else:
                print("Unable to locate server")
        elif choiceSplit[0].lower() == "del":
            fileName = getChoice[4:]
            chord.delete(fileName)
        elif choiceSplit[0].lower() == "down":
            fileName = getChoice[5:]
            if chord.fileExist(fileName):
                progress = 0
                count = 0
                if not os.path.exists("./Download"):
                    os.makedirs("./Download")
                fileNameCrop, fileExtCrop = os.path.splitext(fileName)
                fileCount = 0
                file = "./Download/"+fileName
                while os.path.isfile(file):
                    file = "./Download/"+fileNameCrop+" (" + str(fileCount) + ")"+fileExtCrop
                    fileCount += 1
                f = open(file, 'wb+')
                f.close()
                print("Preparing file for download, please wait")
                while progress < 100:
                    progress = chord.download(fileName, count, file)
                    os.system('cls')
                    if progress == None:
                        print("Download completed")
                        break
                    count += 1
                    print("Download, please wait: %s " %progress)
            else:
                print("Unable to locate file in the system")
            print(" ")
    input("Press enter to continue")

if __name__ == "__main__":
    serverFile = open("./ServerList", 'r')
    serverList = json.load(serverFile)
    while not ('chord' in locals()):
        os.system("cls")
        print("Connecting ")
        time.sleep(1)
        try:
            for x in serverList["Servers"]:
                with Pyro4.locateNS(host=x["IP"], port=(int(x["Port"])-1)) as ns:
                    m = hashlib.md5()
                    connectionConfig = str(x["IP"]) +":"+ str(x["Port"])
                    m.update(connectionConfig.encode('UTF-8'))                    
                    for guidGet, guidURI in ns.list(prefix=str(int(m.hexdigest(), 16))).items():
                        chord = Pyro4.Proxy(guidURI)
        except Exception as e:
            print(str(e))
            time.sleep(1)

    ctypes.windll.kernel32.SetConsoleTitleW(chord.ip +":"+ str(chord.port) + " (" + str(chord.guid) + ")")
    
    while True:
         prompt(chord)
