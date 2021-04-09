import base64
import sys
import os
import time
import socket
import random
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generateRandomString(l):
    mk = ""
    for _ in range(l):
        x = random.randint(0,61)
        if(x<26):
            mk  += chr(ord('A')+x)
        elif(x<52):
            mk += chr(ord('a')+x-26)
        else:
            mk += chr(ord('0')+x-52)
    return mk

def sender(args):
    counter = 0
    for i in range(1, len(args)-1):
        if args[i]=='-n':
            NAME = args[i+1].ljust(12)
            counter += 1
        elif args[i]=='-o':
            OTHER = args[i+1].ljust(12)
            counter += 1
        elif args[i]=='-i':
            INPUTFILE = args[i+1]
            counter+=1
        elif args[i]=='-a':
            KDCIP = args[i+1]
            counter += 1
        elif args[i]=='-p':
            KDCPORT = int(args[i+1])
            counter += 1


    if counter != 5:
        print("Invalid arguments")
        return

    #connect to kdc
    IV = b'\x00'*16
    MYPORT = 10001
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    IP = '127.0.0.1'.ljust(16)
    s.bind((IP, MYPORT))
    print("Using port ", MYPORT)
    s.connect((KDCIP, KDCPORT))

    print("Registering to KDC - ", NAME)
    # send initial regisitration msg
    masterKey = generateRandomString(12)
    # print(masterKey)
    # msg size = 5+16+1+8+1+12+1+12+1 = 57 bytes 
    msg = "|301|"+ IP +"|"+str(MYPORT).ljust(8)+"|"+masterKey+"|"+NAME+"|"
    s.sendall(bytes(msg, 'utf-8'))
    data = s.recv(1024)

    data = data.decode('utf-8').split('|')
    
    if(data[1]!= '302'):
        print("KDC registration failed")
        exit(0)
    s.close()
    print("Registration successful !!!")
    print("Sleeping ...")
    time.sleep(15)

    # generate key from master key using md5
    sender_key = hashlib.md5(bytes(masterKey, 'utf-8')).digest()
    
    #ask for details of other
    nonce1 = generateRandomString(16)
    text = bytes(NAME+ "|" +OTHER+ "|" +nonce1, 'utf-8')
    
    # print(text)
    if len(text)%16 > 0:
        pad = 16-len(text)%16
        text = text + (b'\x00'*pad)
    # print(text)

    cipher = Cipher(algorithms.AES(sender_key), modes.CBC(IV))
    encryptor = cipher.encryptor()
    enc_text = encryptor.update(text) + encryptor.finalize()    
    # print(enc_text)

    enc_text64 = base64.b64encode(enc_text)
    enc_text64 = enc_text64.decode('utf-8')

    msg = bytes("|305|"+enc_text64+"|"+NAME+"|", 'utf-8')

    print("Querying KDC for session with - ", OTHER)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((IP, MYPORT))
    s.connect((KDCIP, KDCPORT))
    s.sendall(msg)
    # print(msg)

    reply = s.recv(1024)
    s.close()
    parts = reply.decode('utf-8').split('|')
    # print(parts)
    opcode = parts[1]
    if(opcode!='306'):
        print("Failed !!!")
        exit(0)

    E_ka64 = parts[2]
    E_ka = base64.b64decode(E_ka64)
    # 160 bytes
    # print(E_ka)
    sender_key = hashlib.md5(bytes(masterKey, 'utf-8')).digest()
    cipher = Cipher(algorithms.AES(sender_key), modes.CBC(IV))
    dec = cipher.decryptor()
    msg = dec.update(E_ka)
    # print(len(msg)) #160 bytes

    msg2 = msg[:80]
    E_kb = msg[80:]

    i = len(msg2)-1
    while(msg2[i]==0):
        i = i-1
    msg2 = msg2[0:i+1]
    
    msg2 = msg2.decode('utf-8').split('|')

    unique_session_code = msg2[0]
    print("Successfully received address and session key from KDC ...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((IP, MYPORT))
    s.connect((msg2[4], int(msg2[5])))

    E_kb64 = base64.b64encode(E_kb).decode('utf-8')

    print("Sending  session key to - ", OTHER)
    transfer_req = "|309|" + E_kb64 + "|" + NAME + "|"
    s.sendall(bytes(transfer_req, 'utf-8'))

    time.sleep(2)
    # encrypt file data
    inpF = open(INPUTFILE, 'r')
    data = inpF.read()
    inpF.close()

    session_key = hashlib.md5(bytes(unique_session_code, 'utf-8')).digest()
    # print(session_key)
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(IV))
    encr = cipher.encryptor()

    data = bytes(data, 'utf-8')
    if len(data)%16>0:
        pad = 16-len(data)%16
        data = data + (b'\x00'*pad)

    enc_data = encr.update(data) + encr.finalize()

    print("Sending encrypted file to ", OTHER)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((IP, MYPORT))
    s.connect((msg2[4], int(msg2[5])))
    
    enc_data64 = base64.b64encode(enc_data).decode('utf-8')

    sending = enc_data64
    s.sendall(bytes(sending, 'utf-8'))
    s.close()
    print("FINISHED \n Exiting ...")
    return

def receiver(args):
    counter = 0
    for i in range(1, len(args)-1):
        if args[i]=='-n':
            NAME = args[i+1].ljust(12)
            counter += 1
        elif args[i]=='-o':
            OUTFILE = args[i+1].ljust(12)
            counter += 1
        elif args[i]=='-s':
            OUTENC = args[i+1]
            counter+=1
        elif args[i]=='-a':
            KDCIP = args[i+1]
            counter += 1
        elif args[i]=='-p':
            KDCPORT = int(args[i+1])
            counter += 1

    if counter != 5:
        print("Invalid arguments")
        return
    
    #connect to kdc
    IV = b'\x00'*16
    MYPORT = 10002
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    IP = '127.0.0.1'.ljust(16)
    s.bind((IP, MYPORT))
    s.connect((KDCIP, KDCPORT))
    print("Using port ", MYPORT)
    print("Registering with KDC - ", NAME)
    # send initial regisitration msg
    masterKey = generateRandomString(12)
    # msg size = 5 + 16 + 1 + 8+ 1 + 12 + 1 + 12 + 1 = 57 bytes
    msg = "|301|"+IP+"|"+str(MYPORT).ljust(8)+"|"+masterKey+"|"+NAME+"|"
    s.sendall(bytes(msg, 'utf-8'))
    data = s.recv(1024)

    data = data.decode('utf-8').split('|')
    
    if(data[1]!= '302'):
        print("KDC registration failed")
        exit(0)
    s.close()
    print("Registration successful !!!")

    time.sleep(2)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((IP, MYPORT))
    s.listen(2)

    conn, addr = s.accept()
    print("Connection request from ", addr)
    data = conn.recv(1024)
    msg = data.decode('utf-8')
    # print(msg)

    opcode = msg[1:4]
    if opcode=='309':
        parts = msg.split('|')

        E_kb64 = parts[2]
        E_kb = base64.b64decode(E_kb64) 

        recv_key = hashlib.md5(bytes(masterKey, 'utf-8')).digest()   
        cipher = Cipher(algorithms.AES(recv_key), modes.CBC(IV))
        decr = cipher.decryptor()        
        msg3 = decr.update(E_kb) + decr.finalize()

        i = len(msg3)-1
        while(msg3[i]==0):
            i -= 1
        msg3 = msg3[0:i+1].decode('utf-8').split('|')
        # print(msg3)
        conn.close()

        unique_session_code = msg3[0]    
        session_key = hashlib.md5(bytes(unique_session_code, 'utf-8')).digest()
        # print(session_key)
        print("Received Session key from - ", msg3[1])
        # receive the file / message
        conn, addr = s.accept()
        data = conn.recv(4096)
        msg = data.decode('utf-8')
        
        print("Connected to ", addr)

        enc_data64 = msg

        encF = open(OUTENC, 'w')
        encF.write(enc_data64)
        encF.close()
        print("Writing encrypted message in base64 format to -", OUTENC)
        enc_data = base64.b64decode(enc_data64)
        # print(enc_data)        

        cipher = Cipher(algorithms.AES(session_key), modes.CBC(IV))
        decr = cipher.decryptor()
        data = decr.update(enc_data) + decr.finalize()

        i = len(data)-1
        while(data[i]==0):
            i -= 1
        data = data[0:i+1]
        # print(data.decode('utf-8'))

        outF = open(OUTFILE, 'w')
        outF.write(data.decode('utf-8'))
        outF.close()
        print("Writing decoded message to -", OUTFILE)
        conn.close()
        s.close()
        print("Exiting ...")
        return
        
    else:
        print("Did not receive code 309 for incoming message \n Exiting ...")
        conn.close()
        s.close()
        exit(0)
    return


if __name__=='__main__':
    argc = len(sys.argv)
    if(argc < 12):
        print("Insufficient arguments")
        exit(0)

    NAME = ""
    MODE = ""

    for i in range(1, argc-1):
        if (sys.argv[i]=='-n'):
            NAME = sys.argv[i+1]
        elif (sys.argv[i]=='-m'):
            MODE = sys.argv[i+1]
    
    if(MODE == 'S'):
        sender(sys.argv)
    elif(MODE == 'R'):
        receiver(sys.argv)
    else:
        print("invalid MODE")
        exit(0)

    