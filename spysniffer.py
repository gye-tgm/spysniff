import socket, sys
from struct import *
import string
import binascii

"""
SpySniffer is a unique low level Python sniffer that can sniff TCP packets and
filters out by certain, and customizable criterias. 
"""

allowed_ports = [8888, 9999]

try:
    # We use AF_INET as the famliy, and set SOCK_RAW as the type of the socket. 
    # IPPROTO_TCP as the protocol 
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error, msg:
    print 'Socket error raised: %s %s' % (str(msg[0]), str(msg[1]))
    sys.exit(1)

while True:
    # We will receive the packet 
    packet = s.recvfrom(65565)[0]

    # We unpack the header accordingly by using the struct.unpack method 
    # https://docs.python.org/2/library/struct.html
    # The exclamation mark at the beginning stands for network (=big endian). 
    # B for unsigned char (1 byte)
    # H for unsigned short (2 byte)
    # 4s for char[4] which will just be interpreted as str in Python
    """
    IP Header (http://tools.ietf.org/html/rfc791):

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    """
    # the IP header consists of 5 * 4 bytes, whose structure is above. 
    iph = unpack('!BBHHHBBH4s4s' , packet[0:20])
    
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
     
    iph_length = ihl * 4
     
    protocol = iph[6]
    src_addr = socket.inet_ntoa(iph[8]);
    dst_addr = socket.inet_ntoa(iph[9]);
     
    """
      TCP Header Format (https://tools.ietf.org/html/rfc793)

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  Data Offset:  4 bits
    The number of 32 bit words in the TCP Header.  This indicates where
    the data begins.  The TCP header (even one including options) is an
    integral number of 32 bits long.
    """

    tcp_header = packet[iph_length:iph_length+20]
    tcph = unpack('!HHLLBBHHH' , tcp_header)
     
    src_port = tcph[0]
    dst_port = tcph[1]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
     
    h_offset = iph_length + tcph_length * 4
     
    data = packet[h_offset:]

    if src_port in allowed_ports or dst_port in allowed_ports:
        if len(data) > 0:
            print 'TCP Packet (version %s) src_addr = %s, dst_addr = %s src/dst port = (%d, %d)' % (version, src_addr, dst_addr, src_port, dst_port)
            print 'Data: '
            print data, len(data)
            print binascii.hexlify(data).decode('ASCII')

