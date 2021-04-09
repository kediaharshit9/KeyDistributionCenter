# CS6500 - Assignment 2 
## KDC based key  establishment
The objective of this assignment is to implement the KDC-based key establishment (exchange) for use with symmetric key encryption algorithms. The data encryption algorithm to be used for client-client and KDC-client communication is: AES-128-CBC, i.e. 128-bit key with CBC mode.

We have implemented 3 roles here:
##### 1. KDC-server
This acts as the center on which users register with their ID and Address. Each user also has aa unique master key shared with the server, which is used to generate a shared key between a specific user and the server. <br />
Any registered user (say A) can query this KDC server to get the address and a session key of another registered user (say B) and some enrypted data which proves authenticity of user A to user B. Also a session key is generated to share data from A to B. <br />
The parameters are as provided in the assignment statement. Example run:
```console
$ python3 kdc.py -p 12345 -o out.txt -f pwd.txt
```
Here: <br />
12345 - is the port on which the server listens to. <br />
out.txt - is the log file. <br />
pwd.txt - is the file in which the server stores the details of registered users.
##### 2. Client (Sender type)
After regisitering with the KDC server, this type of client wishes to get the details of another registered user so that they can send some message/file. <br />
Example run:
```console
$ python3 client.py -n alice -m S -o bob -i inp.txt -a 127.0.0.1 -p 12345
```
Here: <br />
alice - is the name/ID of the user. <br />
S - signifies that the program acts as a sender. <br />
bob - is the name of the person alice wants to send file to. <br />
inp.txt - is the file to be sent to bob. <br />
127.0.0.1 - the IP of KDC server <br />
12345 - the PORT number of KDC server 

##### 3. Client (Receiver type)
After registration with KDC server, this type of client listens to the registered port and waits for encrypted messages from other usuers.