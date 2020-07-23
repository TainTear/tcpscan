# syn扫描
import time
import random
import socket
import sys
from struct import *
import threading

openNum=0
threads = []
list = []

def checksum(msg):
    ''' Check Summing(检验和) '''
    s = 0
    for i in range(0,len(msg),2):
        w = (msg[i] << 8) + msg[i+1]
        s = s+w
    while(s>>16)!=0:
        s = (s>>16) + (s & 0xffff)
    s = ~s & 0xffff
    return s


def CreateSocket(source_ip,dest_ip):
    ''' create socket connection '''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
        s.settimeout(1)
    except:
        print ('Socket create error: ',sys.exc_info()[0],'message: ',sys.exc_info()[1])
        sys.exit()
    return s

def CreateIpHeader(source_ip, dest_ip):
    ''' create ip header '''
    #packet = ''
    # ip header option
    headerlen = 5
    version = 4
    tos = 0
    tot_len = 20+20
    id = random.randrange(18000,65535,1)
    frag_off = 0
    ttl = 255
    protocol = socket.IPPROTO_TCP
    check = 0
    saddr = socket.inet_aton ( source_ip )
    daddr = socket.inet_aton ( dest_ip )
    hl_version = (version << 4) + headerlen
    ip_header = pack('!BBHHHBBH4s4s', hl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)
    return ip_header

def create_tcp_syn_header(source_ip, dest_ip, dest_port):
    ''' create tcp syn header function '''
    source = random.randrange(32000,62000,1) # randon select one source_port
    seq = 0
    ack_seq = 0
    doff = 5
    reserved = 0
    ''' tcp flags '''
    fin = 0
    syn = 1
    rst = 0
    psh = 0
    ack = 0
    urg = 0
    window = socket.htons (8192)    # max windows size
    check = 0
    urg_ptr = 0
    offset_res = (doff << 4) + reserved
    tcp_flags = fin + (syn<<1) + (rst<<2) + (psh<<3) + (ack<<4) + (urg<<5)
    tcp_header = pack('!HHLLBBHHH', source, dest_port, seq, ack_seq, offset_res, tcp_flags, window, check, urg_ptr)

    ''' headers option '''
    source_address = socket.inet_aton( source_ip )
    dest_address = socket.inet_aton( dest_ip )
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
    psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
    psh = psh + tcp_header
    tcp_checksum = checksum(psh)

    ''' Repack the TCP header and fill in the correct checksum '''
    tcp_header = pack('!HHLLBBHHH', source, dest_port, seq, ack_seq, offset_res, tcp_flags, window, tcp_checksum, urg_ptr)

    return tcp_header


def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        source_ip = s.getsockname()[0]
    finally:
        s.close()
    return source_ip

def syn_send_recv(source_ip, dest_ip, port):
    s = CreateSocket(source_ip, dest_ip)
    ip_header = CreateIpHeader(source_ip, dest_ip)
    tcp_header = create_tcp_syn_header(source_ip, dest_ip,port)
    packet_syn = ip_header + tcp_header
    s.sendto(packet_syn,(dest_ip,port))

    global openNum
    try:
        data=s.recvfrom(1024)
        s.close()
    except:
        return 0
    data = data[0]
    ip_header_len = (data[0] & 0x0f) * 4
    ip_header_ret = data[0: ip_header_len - 1]
    tcp_header_len = ((data[32]) & 0xf0)>>2
    tcp_header_ret = data[ip_header_len:ip_header_len+tcp_header_len - 1]
    if (tcp_header_ret[13]) == 0x12:
        openNum += 1
        print("port "+port+" open")
    else:
        print("close")
    s.close()


def main():
    #setdefaulttimeout(1)
    source_ip=get_host_ip() #get my ip
    print(source_ip)
    dest_ip=input('Input dest_ip :')
    dest_port=input('Input dest_port:')
    list = dest_port.split(",")

    for i in range(len(list)):
        if list[i].isdigit():
            t = threading.Thread(target=syn_send_recv, args=(source_ip, dest_ip,int(list[i])))
            threads.append(t)
            t.start()
        else:
            newlist = list[i].split("-")
            startPort = int(newlist[0])
            endPort = int(newlist[1])
            for i in range(startPort,endPort):
                t = threading.Thread(target=syn_send_recv, args=(source_ip, dest_ip,i))
                threads.append(t)
                t.start()
    for t in threads:
        t.join()
    print('[*] The scan is complete!')
    print('[*] A total of %d open port ' % (openNum))


if __name__=="__main__":
    main()