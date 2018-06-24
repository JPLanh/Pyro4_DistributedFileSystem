from datetime import datetime
import os

def log(data):
    try:
        f = open("Logger.txt", 'a+')
    except:
        f = open("Logger.txt", 'w+')
    f.write("[" + str(datetime.now()) + "] " + data + "\n")
    f.close()
    
