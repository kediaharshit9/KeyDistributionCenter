# CS6500 - Assignment 2 
## KDC based key  establishment
The objective of this assignment is to implement the KDC-based key establishment (exchange) for use with symmetric key encryption algorithms. The data encryption algorithm to be used for client-client and KDC-client communication is: AES-128-CBC, i.e. 128-bit key with CBC mode.

We have 3 roles here:
##### 1. KDC-server
This acts as the center on which users register with their ID and Address. Each user also has aa unique master key shared with the server, which is used to generate a shared key between a specific user and the server. 
Any registered user (say A) can query this KDC server to get the address and a session key of another registered user (say B) and some enrypted data which proves authenticity of user A to user B. Also a session key is generated to share data from A to B.
##### 2. Client (Sender type)
After regisitering with the KDC server, this type of client wishes to get the details of another registered user so that they can send some message/file. 
##### 3. Client (Receiver type)
After registration with KDC server, this type of client listens to the registered port and waits for encrypted messages from other usuers.