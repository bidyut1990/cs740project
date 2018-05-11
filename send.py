#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP

from scapy.all import Packet, hexdump
from scapy.all import  StrFixedLenField, XByteField, IntField, BitField
from scapy.all import bind_layers

'''
TENANT HEADER

    bit<32> id;

    bit<32> enq_timestamp;  // 32 bit
    bit<32> enq_qdepth;     // 19      typecast
    bit<32>deq_timedelta;   // 32
    bit<32> deq_qdepth;     // 19      typecast
    bit<32> total_pkt_count;
    bit<32> total_packet_length;
    bit<48> inter_packet_gap;  
'''


class tenant(Packet):
    name = "tenant"
    fields_desc = [ IntField("id", 10),
		    IntField("enq_timestamp",0),
                    IntField("enq_qdepth",0),
                    IntField("deq_timedelta",0),
                    IntField("deq_qdepth",0),
		    IntField("total_pkt_count",0),
		    IntField("total_packet_length",0),
		    BitField("inter_packet_gap",0x0000000000000,48)
                  ]

bind_layers(UDP, tenant, )

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def main():

    if len(sys.argv)<3:
        print 'pass 2 arguments: <destination> "<message>"'
        exit(1)
    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    print "sending on interface %s to %s" % (iface, str(addr))
    for x in range(0,64):
	send_Custom_pkt(x%2)


def send_Custom_pkt(id_t):
    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff') /IP(dst=addr) / UDP(dport=4321, sport=1234) / tenant(id=id_t) / sys.argv[2]
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
	main()
