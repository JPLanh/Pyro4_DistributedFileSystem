import threading
from Pyro4 import naming
import Pyro4

class start_name_server(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        Pyro4.naming.startNSloop(host="0.0.0.0", port=26842)

if __name__ == "__main__":
    nameServer = start_name_server()
    nameServer.start()
    print("Server has been started")
