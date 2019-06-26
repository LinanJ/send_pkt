import socket
import struct
#from gnrs_client import *
import gnrs_client
import logging.config
import sys
# -*- coding: utf-8 -*-
"""
Created on Mon Jan 14 09:54:30 2019

@author: AlecHang
"""


class PktGen():
    def __init__(self):
        self.client = gnrs_client.GnrsClient()
        self.seanet_type = ''
        self.tlv_tag = ''
        self.tlv_length = ''
        self.tlv_value = ''
        self.src_eid = ''
        self.dst_eid = ''
        self.slen = ''
        #self.gnrs_address = address
        #self.gnrs_port = port

    def set_para(self, seanet_type, src_eid, dst_eid, tlv_tag, tlv_length,
                 tlv_value, slen):
        self.seanet_type = seanet_type
        self.src_eid = src_eid
        self.dst_eid = dst_eid
        self.tlv_tag = tlv_tag
        self.tlv_length = tlv_length
        self.tlv_value = tlv_value
        self.slen = slen

    def ping_seanet(self, src_ip, dst_ip):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 255)
        s.setsockopt(0, socket.IP_HDRINCL, 1)
        s.bind(("192.168.100.185", 0))
        # now start constructing the packet

        source_ip = src_ip
        dest_ip = dst_ip

        # ip header fields
        ihl = 5  #shaorted IP pkt
        version = 4  #ipv4
        tos = 0  #no special priority
        tot_len = 0  # total length /kernel will fill this
        id = 0
        frag_off = 0
        ttl = 255
        protocol = 153  #protocol number /seanet is 99
        check = 0
        saddr = socket.inet_aton(
            source_ip)  #Spoof the source ip address if you want to
        daddr = socket.inet_aton(dest_ip)
        ihl_version = (version << 4) + ihl

        # the ! in the pack format string means network order
        # first parameter is formate
        # B is 8, H is 16
        ip_header = struct.pack('!BBHHHBBH4s4s', ihl_version, tos, tot_len, id,
                                frag_off, ttl, protocol, check, saddr, daddr)

        eid = "11111000000000000000000000022222"
        na = "11223344"

        result = self.client.register(
            self.src_eid, self.dst_eid, eid, na, self.seanet_type,
            self.tlv_tag, self.tlv_length, self.tlv_value, self.slen)
        
        
        packet = ip_header + result
        s.sendto(packet, (dst_ip, 97))
        logging.info(result)


#the src_ip and dst_ip should be the host ip
if __name__ == '__main__':

    pkt = PktGen()
    src_ip = "192.168.100.185"
    #src_ip = "192.168.112.1"
    dst_ip = "192.168.101.14"
    slen = 80#slen目前似乎没啥用
    seanet_type = "02"
    src_eid = "00000000000000000000000000000003"  #h1-EID
    dst_eid = "00000000000000000000000000000001"  #h2-EID
    pkt.set_para(seanet_type, src_eid, dst_eid, "", "", "", slen)
    pkt.ping_seanet(src_ip, dst_ip)
