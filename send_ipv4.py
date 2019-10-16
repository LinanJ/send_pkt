import socket
import struct
#import gnrs_client
import logging.config
import sys
import binascii
# -*- coding: utf-8 -*-
"""
Created on Mon Jan 14 09:54:30 2019

@author: AlecHang
"""


class PktGen():
    def __init__(self, payload_hex):
        #16进制payload，可以自定义更多字段
        self.payload_hex = payload_hex

    def send_packet(self, src_ip, dst_ip, dst_port, NIC):
        #采用原始套接字进行数据包发送
        s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW,
                          socket.htons(0x0800))
        #s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 255)
        #s.setsockopt(0, socket.IP_HDRINCL, 1)
        #绑定特定IP网卡，如果注释掉这一句则使用默认网卡
        #s.bind((src_ip, 0))
        s.bind((NIC, socket.htons(0x0800)))

        src_mac = b'\xaa\xaa\xaa\xaa\xaa\xaa'
        dst_mac = b'\xbb\xbb\xbb\xbb\xbb\xbb'
        eth_type = b'\x08\x00'

        # now start constructing the packet
        source_ip = src_ip
        dest_ip = dst_ip

        # ip header fields
        ihl = 5  #shaorted IP pkt
        version = 4  #ipv4
        tos = 0  #no special priority
        tot_len = 44  # total length /kernel will fill this
        id = 0
        frag_off = 0
        ttl = 255
        protocol = 153  #protocol number /seanet is 99
        check = 0
        saddr = socket.inet_aton(source_ip)  #Spoof the source ip address if you want to
        daddr = socket.inet_aton(dest_ip)
        ihl_version = (version << 4) + ihl

        # the ! in the pack format string means network order
        # first parameter is formate
        # B is 8, H is 16
        ip_header = struct.pack('!6s6s2sBBHHHBBH4s4s', src_mac, dst_mac, eth_type, ihl_version, tos, tot_len, id,
                                frag_off, ttl, protocol, check, saddr, daddr)
      
        #2进制
        payload_bin = binascii.a2b_hex(self.payload_hex)

        packet = ip_header + payload_bin

        #将数据包发送给ip为dst_ip,端口号为dst_port的主机
        s.send(packet)


def help_send():
    print("\nUsage: \n \
    python2 send_ipv4.py <NIC_name> <packet_num>\n")

def main(argv):

    if len(argv) < 3 :
        help_send()
        exit()

    if not argv[1]:
        exit("please inut NIC name")
        
    if not argv[2]:
        exit("please inut send pkt_num")


    NIC = argv[1] #NIC
    num_pkt = int(argv[2])  #num_pkt


    pkt = PktGen('1234567890')
    src_ip = "192.168.100.185"
    dst_ip = "224.0.0.102"
    dst_port = 369
    
    for i in range(num_pkt):
        pkt.send_packet(src_ip, dst_ip, dst_port, NIC)


#the src_ip and dst_ip should be the host ip
if __name__ == '__main__':
    main(sys.argv)
    
