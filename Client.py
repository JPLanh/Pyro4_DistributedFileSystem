import Pyro4
from Pyro4 import naming
import hashlib
import sys
import os
import ctypes
import time
import json
import datetime
import constant
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
    tokenList = []
    fileList = []
    m = hashlib.md5()
    m.update("MetaData".encode('utf-8'))
    metaData['tokens'] = tokenList
    metaData["files"] = fileList  
    f = open(constant.USB_DIR+str(int(m.hexdigest(), 16)), 'w')
    json.dump(metaData, f)
    f.close()

def readMetaData(dataReader):
    m = hashlib.md5()
    m.update("MetaData".encode('utf-8'))
    meta = int(m.hexdigest(), 16)
    jread = open(constant.USB_DIR+str(meta), 'r')
    jsonRead = json.load(jread)
    jread.close()
    return jsonRead[dataReader]

def writeMetaData(dataReader, rawData):
    m = hashlib.md5()
    m.update("MetaData".encode('utf-8'))
    meta = int(m.hexdigest(), 16)
    jread = open(constant.USB_DIR+str(meta), 'w')
    metadata = {}
    metadata[dataReader] = rawData
    json.dump(metadata, jread)
    jread.close()
      
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
            showDirectory(chord)
        elif choiceSplit[0].lower() == "key":
            chord.keyPrint()
        elif choiceSplit[0].lower() == "sync":
            sync()
        elif choiceSplit[0].lower() == "ring":
            chord.successor.ringAround(chord, 0)
        elif choiceSplit[0].lower() == "finger":
            chord.printFinger()
        elif choiceSplit[0].lower() == "sap":
            print(chord.simplePrint())
        elif choiceSplit[0].lower() == "reg":
            register(chord)
    elif len(choiceSplit) > 1:
        if choiceSplit[0].lower() == "up":
            upload(chord, getChoice[3:])
        elif choiceSplit[0].lower() == "join":
            if len(choiceSplit) == 3:
                joinRing(chord, choiceSplit[1], str(choiceSplit[2]))
        elif choiceSplit[0].lower() == "del":
            chord.delete(getChoice[4:])
        elif choiceSplit[0].lower() == "down":
            download(chord, getChoice[5:])
        elif choiceSplit[0].lower() == "shutdown":
            chord.shutDown(chord)
    input("Press enter to continue")
    

def delete(chord, fileName):
    try:
        tempMetaData = readMetaData("files")
        for x in tempMetaData:
            if x['File Name'] == fileName:
                for y in x['Pages']:
                    locateChord = chord.locateSuccessor(y['Guid'])
                    locateChord.removePage(y['Guid'])
                tempMetaData.remove(x)
                writeMetaData('files', tempMetaData)
    except Exception as e:
        print(str(e))

def sync(chord):
    tempMetaData = readMetaData("tokens")
    ##WE NEED TO GET THE RSAINFO somehow
            
def upload(chord, fileName):
    os.path.isfile(fileName)
    tempMetaData = readMetaData("files")
    f = open(fileName, 'rb')
    data = f.read()
    tokenDigest = hashlib.md5()
    tokenDigest.update((fileName + ":::" + str(datetime.datetime.now())).encode('utf-8'))
    f.close()
    fileInfo = {}
    fileInfo['File Name'] = fileName
    fileInfo['Token'] = int(tokenDigest.hexdigest(), 16)
    fileInfo['Total Pages'] = 0
    fileInfo['Page Size'] = chord.calculateSize(len(data))
    fileInfo['File Size'] = 0
    pages = []
    fileInfo['Pages'] = pages
   # while fileInfo['File Size'] < len(data):
    newPage = {}
    m = hashlib.md5()
    IPGet = fileName + ":" + str(fileInfo['Total Pages'])
    m.update(IPGet.encode('utf-8'))
    newPage["Page"] = fileInfo['Total Pages']
    fileInfo['Total Pages'] += 1
    if (len(data) - fileInfo['File Size']) > fileInfo['Page Size']:
        dataSegment = data[fileInfo['File Size']:(fileInfo['File Size']+fileInfo['Page Size'])]        
        newPage['Size'] = fileInfo['Page Size']
        fileInfo['File Size'] += fileInfo['Page Size']
    else:
        dataSegment = data[fileInfo['File Size']:len(data)]
        newPage['Size'] = len(data) - fileInfo['File Size']
        fileInfo['File Size'] += newPage['Size']
#        chordGet = chord.locateSuccessor(int(m.hexdigest(), 16))
    fileGuid = chord.upload(fileName, b64encode(dataSegment).decode('UTF-8'), fileInfo['Total Pages'], fileInfo['Token'])
    newPage["Guid"] = fileGuid
    fileInfo['Pages'].append(newPage)
    print("Partial upload complete")
## end of indentation of the while loop
    tempMetaData.append(fileInfo)
    writeMetaData('files', tempMetaData)

def download(chord, fileName):    
    metaData = readMetaData("files")
    for x in metaData:
        if x['File Name'] == fileName:
            if not os.path.exists("./Download"):
                os.makedirs("./Download")
                fileNameCrop, fileExtCrop = os.path.splitext(fileName)
            while os.path.isfile(file):
                file = "./Download/"+fileNameCrop+" (" + str(fileCount) + ")"+fileExtCrop
                fileCount += 1
            f = open(file, 'wb+')
            f.close()
            for y in x['Pages']:
                f.open(file, 'wb')
                f.write(chord.download(x['File Name'], y['Guid'], y['Page'], b64encode(reversed(y['RSAInfo'])).decode('UTF-8')))
                f.close()
                           
def downloadOld(chord, fileName):    
    metaData = readMetaData("files")
    for x in metaData:
        if x['File Name'] == fileName:
            pages = x['Total Pages']
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

def showDirectory(chord):
    try:
        metadata = readMetaData("files")
        for x in metadata:
            print("%s  |  %s  |  %s" %(x['File Name'], x['File Size'], x['Total Pages']))
    except FileNotFoundError as e:
        print("USB not recognized, now aborting")

def joinRing(chord, getIP, getPort):
    if (getIP == chord.ip) and (getPort == chord.port):
        print("Unable to join the same chord")
    else:
        try:
            m = hashlib.md5()
            IPGet = getIP + ":" + getPort
            m.update(IPGet.encode('utf-8'))
            try:
                print(chord.joinRing(getIP, getPort, int(m.hexdigest(), 16)))
            except Pyro4.errors.NamingError:
                print("Unable to locate server")
        except Exception as e:
            print(str(e))

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
