# Aegis System of Distributing Files (ASDF)

A Distributed File System that partition and encrpyt a given file and store it on a peer-2-peer system.

## Getting Started

Atleast two Amazon AWS EC2 instance should be running, but for the time being the two server being:
1. ec2-18-218-220-102.us-east-2.compute.amazonaws.com
2. ec2-18-191-99-22.us-east-2.compute.amazonaws.com

### Prerequisites

N/A

### Installation

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
