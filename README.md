# Aegis System of Distributing Files (ASDF)

A Distributed File System that partition and encrpyt a given file and store it on a peer-2-peer (chord) system.

## Getting Started

Name Server: The yellow book of your servers, your server will try to communicate to this server and enlist them in the system.
Server: The peer-2-peer servers that you will be connected to and most of the operation happening.
Client: You, or the controller.

### Prerequisites

API: Pyro4, Cryptography
Resource: 2+ cloud services (a server, and a name server)

### Installation

Python 3.x
 1. sudo apt-get update
 2. sudo apt-get install python3-pip
 3. sudo pip3 install pyro4
 4. sudo pip3 install cryptography
 
###### Name Server Side

A name server will need to have `nameServer.py` running.

A name server requires the following file:
- nameServer.py

###### Server Side

A server will need to have `Server.py` running.

A server requires the following files:
- Server.py
- Constant.py
- Chord.py
- Encryptor.py
- Decryptor.py
- Logger.py

###### Client Side

User will have to run `Client.py`.

A Client requires the following files:
 - Chord.py
 - Constant.py
 - Client.py

## Deployment

### Built With
* [Pyro4] (https://pythonhosted.org/Pyro4/install.html) - The Remote Invocation Package used for python3
* [Hazmat Cryptography] (https://cryptography.io) - Use to implement security

## Author
* **Jimmy Lanh**

## Acknowledgments
* **Professor Oscar Morales-Ponce** - for introducing and having us implement the Distributed File System, even though it was on java, the fundamental was able to be implemented into python, and also the idea of block chaining encryption.
* **Professor Mehrdad Aliasgari** - for shedding light on the world of cyber security and have us implement a ransomware system where we are to encrpyt an decrypt files.
* **Yurika Mori** - My girlfriend who patiently supported me considering how she put up with my endless hour of coding at starbucks, and also criticized my system.
