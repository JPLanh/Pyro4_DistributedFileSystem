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
import threading
import Encryptor
import Decryptor
from Chord import Chord
from base64 import b64encode, b64decode

#Register the user creating a private key and metadata
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

def readMetaData():
    m = hashlib.md5()
    m.update("MetaData".encode('utf-8'))
    meta = int(m.hexdigest(), 16)
    jread = open(constant.USB_DIR+str(meta), 'r')
    jsonRead = json.load(jread)
    jread.close()
    return jsonRead

def writeMetaData(data):
    m = hashlib.md5()
    m.update("MetaData".encode('utf-8'))
    meta = int(m.hexdigest(), 16)
    jread = open(constant.USB_DIR+str(meta), 'w')
    json.dump(data, jread)
    jread.close()

#Prompt the user of the main menu         
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
            sync(chord)
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
        elif choiceSplit[0].lower() == "rem":
            delete(chord, getChoice[4:])
        elif choiceSplit[0].lower() == "down":
            download(chord, getChoice[5:])
        elif choiceSplit[0].lower() == "shutdown":
            chord.shutDown(chord)
    input("Press enter to continue")
    
#Remove the file, and the following pages that corresponds to the file
def delete(chord, fileName):
    try:
        tempMetaData = readMetaData()
        for x in tempMetaData['files']:
            if x['File Name'] == fileName:
                print("Removing " + x['File Name'] + " please wait.") 
                for y in x['Pages']:
                    locateChord = chord.locateSuccessor(int(y['Guid']))
                    locateChord.removePage(y['Guid'])
                tempMetaData['files'].remove(x)
                writeMetaData(tempMetaData)
    except Exception as e:
        print(str(e))

#Synchronize the user's receipt with the server, technically retrieving the
#corresponding metadata components.
def sync(chord):
    print("Synchronizing, please wait")
    tempMetaData = readMetaData()
    for x in tempMetaData['tokens']:
        for y in tempMetaData['files']:
            if y['Sync'] == "No":
                for z in y['Pages']:
                    m = hashlib.md5()
                    combo = str(z['Guid']) + ":" + str(x)
                    getChord = chord.locateSuccessor(int(z['Guid']))
                    m.update(combo.encode('UTF-8'))
                    packageRetrieved = getChord.sync(str(int(m.hexdigest(), 16)))
                    for packObject in packageRetrieved:
                        z['RSAInfo'].append(packObject)
                y['Sync'] = "Yes"
        tempMetaData['tokens'].remove(x)
        writeMetaData(tempMetaData)
    print("Synchronize complete")

#Partition the file's data into a smaller segment and append them to the respective
#pages. It first encrypt the file and then send it over.
def upload(chord, fileName):
    os.path.isfile(fileName)
    tempMetaData = readMetaData()
    f = open(fileName, 'rb')
    data = f.read()
    tokenDigest = hashlib.md5()
    tokenDigest.update((fileName + ":::" + str(datetime.datetime.now())).encode('utf-8'))
    tokenReceipt = int(tokenDigest.hexdigest(), 16)
    f.close()
    fileInfo = {}
    fileInfo['File Name'] = fileName
    fileInfo['Total Pages'] = 0
    fileInfo['Sync'] = "No"
    fileInfo['Page Size'] = chord.calculateSize(len(data))
    fileInfo['File Size'] = 0
    pages = []
    fileInfo['Pages'] = pages
    while fileInfo['File Size'] < len(data):
        newPage = {}
        m = hashlib.md5()
        IPGet = fileName + ":" + str(fileInfo['Total Pages'])
        m.update(IPGet.encode('utf-8'))
        newPage["Page"] = fileInfo['Total Pages']
        if (len(data) - fileInfo['File Size']) > fileInfo['Page Size']:
            dataSegment = data[fileInfo['File Size']:(fileInfo['File Size']+fileInfo['Page Size'])]        
            newPage['Size'] = fileInfo['Page Size']
            fileInfo['File Size'] += fileInfo['Page Size']
        else:
            dataSegment = data[fileInfo['File Size']:len(data)]
            newPage['Size'] = len(data) - fileInfo['File Size']
            fileInfo['File Size'] += newPage['Size']
        uploadPage = upload_file_thread(fileName, dataSegment, newPage, fileInfo, tokenReceipt)
        uploadPage.start()
    tempMetaData['tokens'].append(int(tokenDigest.hexdigest(), 16))
    writeMetaData(tempMetaData)

#Grab the receipt of the file and get all the the following pages and data
#from the server.
def download(chord, fileName):    
    metaData = readMetaData()
    for x in metaData['files']:
        if x['File Name'] == fileName:
            if not os.path.exists("./Download"):
                os.makedirs("./Download")
            fileNameCrop, fileExtCrop = os.path.splitext(fileName)
            absoluteFile = "./Download/" + fileName
            fileCount = 0
            while os.path.isfile(absoluteFile):
                print("file Exist: " + absoluteFile)
                absoluteFile = "./Download/"+fileNameCrop+" (" + str(fileCount) + ")"+fileExtCrop
                fileCount += 1
            f = open(absoluteFile, 'wb+')
            for y in x['Pages']:                
                getLastPT = chord.download(x['File Name'], y['Guid'], y['Page'], y['RSAInfo'])
                for z in y['RSAInfo']:
                    if z['Set'] == 0:
                        f.write(b64decode(Decryptor.initialize(b64decode(z['RSACipher']), b64decode(getLastPT), b64decode(z['IV']), b64decode(z['Tag']), None)))
            f.close()

#Show the metadata of what the user have, and not the server.
def showDirectory(chord):
    try:
        metadata = readMetaData()
        for x in metadata['files']:
            print("%s  |  %s  |  %s | Synced: %s" %(x['File Name'], x['File Size'], x['Total Pages'], x['Sync']))
    except FileNotFoundError as e:
        print("USB not recognized, now aborting")

#Allow the user to join the ring and attaching itself to one of the nodes.
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

class upload_file_thread(threading.Thread):
    def __init__(self, fileName, data, page, fileInfo, tokenReceipt):
        threading.Thread.__init__(self)
        self.fileName = fileName
        self.dataSegment = data
        self.page = page
        self.fileInfo = fileInfo
        self.tokenReceipt = tokenReceipt

    def run(self):
        RSACipher, cipherText, IV, tag = Encryptor.initialize(b64encode(self.dataSegment).decode('UTF-8'))
        privKey = open(constant.CHORD_PRIV_PEM, 'rb')
        fileGuid = chord.upload(self.fileName, cipherText, self.page["Page"], self.page, privKey.read())
        self.page["Guid"] = fileGuid
        self.page["RSAInfo"] = []
        self.page["RSAInfo"].append({"Tag": tag, "RSACipher": RSACipher, "IV": IV, "Set": 0})
        fileInfo['Pages'].append(newPage)
        fileInfo['Total Pages'] += 1
        

if __name__ == "__main__":
    serverFile = open("./ServerList", 'r')
    serverList = json.load(serverFile)
    Pyro4.config.COMMTIMEOUT = 3
    while not ('chord' in locals()):
        os.system("cls")
        print("Connecting ")
        time.sleep(1)
        try:
            with Pyro4.locateNS(host="35.212.249.77", port=constant.SERVER_PORT) as ns:
                for guidGet, guidURI in ns.list().items():
                     print(guidGet)
                     chord = Pyro4.Proxy(guidURI)
                     print(chord.ip)
                     break
        except Exception as e:
            print(str(e))
            time.sleep(1)

    ctypes.windll.kernel32.SetConsoleTitleW(chord.ip +":"+ str(chord.port) + " (" + str(chord.guid) + ")")
    
    while True:
         prompt(chord)
