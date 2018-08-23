from datetime import datetime
import os

def log(data):
    try:
        f = open("Logger.txt", 'a+')
    except:
        f = open("Logger.txt", 'w+')
    f.write("[" + str(datetime.now()) + "] " + data + "\n\n")
    f.close()

    
def printLog(data):
    print("[" + str(datetime.now()) + "] " + data)
##to catch and print out the exception error
#    try:
#       code here to catch
#    except Exception as e:
#       Logger.log(str(e))
#
