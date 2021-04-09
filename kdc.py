import base64
import sys
import os
import socket
import random
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Registrants:
    def __init__(self, ip, port, mk):
        self.ip = ip
        self.port = port
        self.mk = mk

def generateSessionKey(l):
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

if __name__=='__main__':
    argc = len(sys.argv)
    if(argc < 7):
        print("Insufficient arguments")
        exit(0)

    counter=0

    PORT = 0
    PWD = ""
    LOGS = ""

    for i in range(1, argc-1):
        if(sys.argv[i] == '-p'):
            PORT = int(sys.argv[i+1])
            counter += 1
        elif(sys.argv[i]=='-o'):
            LOGS = sys.argv[i+1]
            counter += 1
        elif(sys.argv[i]== '-f'):
            PWD = sys.argv[i+1]
            counter += 1
    
    if (counter != 3):
        print("invalid arguments, use: kdc -p port -o outfile -f pwdfile")
        exit(0)
    
    logfile = open(LOGS, 'w')
    users = {}
    #bind to socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    s.bind(('', PORT))

    print("Listening on port ", PORT)
    print("For details see - ", LOGS)
    print("Press Ctrl+C to exit")
    s.listen(2)

    while True:
        conn, addr = s.accept()
        logfile.write("Connected to "+ str(addr) +"\n")
        
        data = conn.recv(1024)
        msg = data.decode('utf-8')
        # print(msg)

        opcode = msg[1:4]
        if (opcode == '301'):
            parts = msg.split('|')
            # print(parts)
            obj = Registrants(parts[2], parts[3], parts[4])
            users[parts[5]] = obj
                
            pwdfile = open(PWD,'w')
            for x in users.keys():
                b64mk = base64.b64encode(bytes(users[x].mk, 'utf-8'))
                data = ":" + x + ":"+ users[x].ip +":"+ users[x].port+":"+ b64mk.decode('utf-8') +":"
                pwdfile.write(data + "\n")
            pwdfile.close()  

            reply = "|302|" + parts[5] + "|"
            conn.sendall(bytes(reply, 'utf-8'))
            conn.close()
            logfile.write("Registered " + parts[5] + '\n')
            logfile.write("Closing connection...\n")

        elif (opcode=='305'):
            parts = msg.split('|')
            
            sender_name = parts[3]
            masterKey = users[sender_name].mk
            sender_key = hashlib.md5(bytes(masterKey, 'utf-8')).digest()

            enc_text64 = parts[2]
            enc_text = base64.b64decode(enc_text64)
            # print(enc_text)

            IV = b'\x00'*16
            cipher = Cipher(algorithms.AES(sender_key), modes.CBC(IV))
            decryptor = cipher.decryptor()
            text = decryptor.update(enc_text) + decryptor.finalize()
            # print(text)

            i = len(text) -1
            while(text[i]==0):
                i = i-1
        
            text = text[0:i+1]
            # print(text)
            
            text = text.decode('utf-8').split('|')
            ID_A = text[0]
            ID_B = text[1]
            nonce1 = text[2]

            # generate a session key
            K_s = generateSessionKey(8)

            if ID_A not in users.keys():
                logfile.write("Unregistered user is asking for query\n")
                s.sendall(bytes("|404| Register please", 'utf-8'))
                conn.close()
                continue
            elif ID_B not in users.keys():
                logfile.write("Asing for Unregistered user\n")
                s.sendall(bytes("|404| User not found", 'utf-8'))
                conn.close()
                continue

            details_A = users[ID_A]
            details_B = users[ID_B]

            # reply = |306 | E_A(msg2 || E_b(msg3))
            msg3 = K_s + "|" + ID_A + "|" + ID_B + "|" + nonce1 + "|" + details_A.ip + "|" + details_A.port
            # print(msg3)
            msg2 = K_s + "|" + ID_A + "|" + ID_B + "|" + nonce1 + "|" + details_B.ip + "|" + details_B.port +"|"
            # print(msg2)

            mk_A = details_A.mk
            mk_B = details_B.mk
            keyA = hashlib.md5(bytes(mk_A, 'utf-8')).digest()
            keyB = hashlib.md5(bytes(mk_B, 'utf-8')).digest()
            cipherA = Cipher(algorithms.AES(keyA), modes.CBC(IV))
            cipherB = Cipher(algorithms.AES(keyB), modes.CBC(IV))
            enc1 = cipherA.encryptor()
            enc2 = cipherB.encryptor()

            msg3 = bytes(msg3, 'utf-8')
            if len(msg3)%16 > 0:
                pad = 16-len(msg3)%16
                msg3 = msg3 + (b'\x00'*pad)
            # made 80 bytes
            E_kb = enc2.update(msg3) + enc2.finalize()

            msg2 = bytes(msg2, 'utf-8')
            if len(msg2)%16>0:
                pad = 16-len(msg2)%16
                msg2 = msg2 + (b'\x00'*pad)
            
            msg2 = msg2 + E_kb
            E_ka = enc1.update(msg2) + enc1.finalize()            
            # print(E_ka)
            E_ka64 = base64.b64encode(E_ka).decode("utf-8")

            reply = "|306|" + E_ka64

            conn.sendall(bytes(reply, 'utf-8'))
            conn.close()
            logfile.write("Sent " + ID_A +" details of "+ ID_B+ '\n')
            logfile.write("Closing connection...\n")
    
    s.close()
    logfile.close()