from socket import *
import socket
import os
import sys
import struct
import time
import select
import binascii
import pandas as pd

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 1

def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2

    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def build_packet():
    myChecksum = 0
    ID = os.getpid() & 0xFFFF
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())
    myChecksum = checksum(header + data)
    if sys.platform == "darwin":
        myChecksum = htons(myChecksum) & 0xFFFF
    else:
        myChecksum = htons(myChecksum)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data
    return packet

def is_unavailable(hostname):
    if hostname == "timeout":
        return "timeout"
    if hostname == "hostname not returnable":
        return "0"
    return "11"

def get_route(hostname):
    timeLeft = TIMEOUT
    df = pd.DataFrame()
    tracelist1 = []
    tracelist2 = []

    for ttl in range(1, MAX_HOPS):
        for tries in range(TRIES):
            destAddr = gethostbyname(hostname)
            icmp = socket.getprotobyname("icmp")
            mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
            # Fill in end

            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)

            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if whatReady[0] == []: # Timeout
                    tracelist2.append(["*", "*", "*", "timeout"])
                
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    tracelist2.append(["*", "*", "*", "timeout"])
                    
            except:
                continue
        
            else:
                icmpHeader = recvPacket[20:28]
                request_type, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)
                
                try: 
                    hostaddr = gethostbyaddr(addr[0])[0]
                    
                except: 
                    hostaddr = "hostname not returnable"
                    # Fill in end
                if request_type == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    # Fill in start
                    stringaddr = str(addr[0])
                    stringttl = str(ttl)
                    stringms = str((timeReceived - t) * 1000)
                    tracelist2.append((stringttl, stringms, stringaddr, hostaddr))
                    
                elif request_type == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    # Fill in start
                    stringaddr = str(addr[0])
                    stringttl = str(ttl)
                    stringms = str((timeReceived - t) * 1000)
                    tracelist2.append((stringttl, stringms, stringaddr, hostaddr))
                    
                elif request_type == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    # Fill in start
                    stringaddr = str(addr[0])
                    stringttl = str(ttl)
                    stringms = str((timeReceived-t) * 1000)
                    tracelist2.append((stringttl, stringms, stringaddr, hostaddr))
                    
                else:
                    # Fill in start
                    print("error")
                    
                break
            finally:
                mySocket.close()
    
    df = pd.DataFrame(tracelist2, columns=['Hop Count', 'Try', 'IP', 'Hostname'])
    df['Response Code'] = df['Hostname'].apply(is_unavailable)
    return df

if __name__ == '__main__':
    tracelist = get_route("google.co.il")
    print(tracelist)