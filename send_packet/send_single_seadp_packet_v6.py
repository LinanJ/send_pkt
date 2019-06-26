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
        # ID首部
        self.id_next_head_type = ''  # 8bit
        self.id_length = 0  # 8bit
        self.id_seanet_prot_pro = 0  # 16bit
        self.src_guid = ''  # 160bit
        self.dst_guid = ''  # 160bit
        # SeaDP首部
        self.seadp_src_port = ''  # 16bit
        self.seadp_dst_port = ''  # 16bit
        self.seadp_packet_type = ''  # 8bit
        self.seadp_cache_type = ''  # 8bit
        self.seadp_tran_type_res = ''  # 16bit
        self.seadp_chunk_total_len = ''  # 32bit
        self.seadp_packet_offset = ''  # 32bit
        self.seadp_packet_order = ''  # 16bit
        self.header_checksum = ''  # 16bit

        self.payload = ''

    def set_para(self, id_next_head_type, id_length, id_seanet_prot_pro, src_guid, dst_guid,
                 src_port, dst_port, packet_type, cache_type, tran_type_res, chunk_total_len,
                 packet_offset, packet_order, payload):
        # ID首部
        self.id_next_head_type = id_next_head_type
        self.id_length = id_length
        self.id_seanet_prot_pro = id_seanet_prot_pro
        self.src_guid = src_guid
        self.dst_guid = dst_guid
        # SeaDP首部
        self.seadp_src_port = src_port
        self.seadp_dst_port = dst_port
        self.seadp_packet_type = packet_type
        self.seadp_cache_type = cache_type
        self.seadp_tran_type_res = tran_type_res
        self.seadp_chunk_total_len = chunk_total_len
        self.seadp_packet_offset = packet_offset
        self.seadp_packet_order = packet_order

        self.payload = payload

    def ping_seanet(self, src_ip, dst_ip, ipv6_payload_len):
        s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW,
                          socket.htons(0x86dd))
        #s.setsockopt(0, socket.IP_HDRINCL, 1)

        # now start constructing the packet

        source_ip = "fe80::49e8:4a9a:faf1:8779"
        dest_ip = 'ff02::1:ff0f:cd7d'

        s.bind(("em4", socket.htons(0x86dd)))

        # eth header fields
        src_mac = b'\xaa\xaa\xaa\xaa\xaa\xaa'
        dst_mac = b'\xbb\xbb\xbb\xbb\xbb\xbb'
        eth_type = b'\x86\xdd'

        # ipv6 header fields
        version = 6
        traffic_class = 0
        flowlabel_1 = 0  # first 4 bit of flowlabel
        flowlabel_2 = 0  # last 16 bit of flowlabel
        total_len = ipv6_payload_len
        next_header = 153
        hop_limit = 253
        version_traffic_flow = (version << 12) + \
            (traffic_class << 4) + flowlabel_1
        src_ipv6 = socket.inet_pton(socket.AF_INET6, source_ip)
        dst_ipv6 = socket.inet_pton(socket.AF_INET6, dest_ip)
        ipv6_header = struct.pack('!6s6s2sHHHBB16s16s', src_mac, dst_mac, eth_type, 
                                version_traffic_flow, flowlabel_2,
                                total_len, next_header, hop_limit, src_ipv6, dst_ipv6)

        #eid = "11111000000000000000000000022222"
        #na = "11223344"

        result = self.client.seadp_register(self.id_next_head_type, self.id_length, self.id_seanet_prot_pro, self.src_guid, self.dst_guid,
                                            self.seadp_src_port, self.seadp_dst_port, self.seadp_packet_type, self.seadp_cache_type, self.seadp_tran_type_res,
                                            self.seadp_chunk_total_len, self.seadp_packet_offset, self.seadp_packet_order, self.payload)

        packet = ipv6_header + result
        s.send(packet)
        logging.info(result)


# the src_ip and dst_ip should be the host ip
if __name__ == '__main__':

     # init parameters
    pkt = PktGen()
    src_ip = "192.168.120.14"
    #dst_ip = "192.168.150.241"
    #src_ip = "192.168.100.185"
    dst_ip = "192.168.120.16"

    payload_len = 1364#id 44 bytes, seadp 20 bytes, payload 1300 bytes

    # ID head
    id_next_head_type = "01"
    id_length = "2C"
    id_seanet_prot_pro = "4444"
    src_guid = "1234000000000000000000000000000000001236"  # h1-EID
    dst_guid = "5678000000000000000000000000000000005678"  # h2-EID

    # SeaDP head
    src_port = "1357"
    dst_port = "2468"
    packet_type = "80"
    cache_type = "01"
    tran_type_res = "2222"
    # chunk size is 2MB, 2048*1024 = 2^21 = 2097152 B,in hex is 00200000
    chunk_total_len = "00200000"
    # each payload is 1300 B except the last one, which is 252 B
    packet_offset = "00000000"
    packet_order = "0001"

    # check_sum for seaDP will be filled when construct a SeaDP packet (in function seadp2byte())

    # payload is 1300 B
    payload = "ffffffffff"
    i = 0
    for i in range(2590):
        # chr function is used to transform the ascii to char
        payload += '5'
        #payload += chr(random.randint(65, 70))

    pkt.set_para(id_next_head_type, id_length, id_seanet_prot_pro, src_guid, dst_guid,
                 src_port, dst_port, packet_type, cache_type, tran_type_res, chunk_total_len,
                 packet_offset, packet_order, payload)

    # construct IP packet and send
    #pkt.ping_seanet(src_ip, dst_ip)

    #pkt.seadp_packet_order = "5432"
    #pkt.ping_seanet(src_ip, dst_ip)
    # print("发包结束")
    packet_order_count = 1
    offset_bigen = 0
    offset_hex = 0
    #yy = format(xx, 'x')

    pkt.seadp_packet_order = '{:0>4}'.format(packet_order)
    pkt.seadp_packet_offset = '{:0>8}'.format(offset_hex)
    pkt.ping_seanet(src_ip, dst_ip, payload_len)

    print("发包结束")
