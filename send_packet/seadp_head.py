import binascii
import sys
from util import int2byte

#ID首部生成时一并放在SeaDP报文中
class SeaDPPacket():
    def __init__(self):
        #ID首部
        self.id_next_head_type = ''#8bit
        self.id_length = 0#8bit
        self.id_seanet_prot_pro = 0 #16bit
        self.src_guid = ''#160bit
        self.dst_guid = ''#160bit
        #SeaDP首部
        self.seadp_src_port = ''#16bit
        self.seadp_dst_port = ''#16bit
        self.seadp_packet_type = ''#8bit
        self.seadp_cache_type = ''#8bit
        self.seadp_tran_type_res = ''#16bit
        self.seadp_chunk_total_len = ''#32bit
        self.seadp_packet_offset = ''#32bit
        self.seadp_packet_order = ''#16bit
        self.header_checksum = ''#16bit
        #self.tlv = binascii.a2b_hex('')
        #self.payload = binascii.a2b_hex('')



    def setHeader(self, id_next_head_type, id_length, id_seanet_prot_pro, src_guid, dst_guid,
                  src_port, dst_port, packet_type, cache_type, tran_type_res, chunk_total_len, packet_offset, packet_order):
        #ID首部
        self.id_next_head_type = id_next_head_type
        self.id_length = id_length
        self.id_seanet_prot_pro = id_seanet_prot_pro
        self.src_guid = src_guid
        self.dst_guid = dst_guid
        #SeaDP首部
        self.seadp_src_port = src_port
        self.seadp_dst_port = dst_port
        self.seadp_packet_type = packet_type
        self.seadp_cache_type = cache_type
        self.seadp_tran_type_res = tran_type_res
        self.seadp_chunk_total_len = chunk_total_len
        self.seadp_packet_offset = packet_offset
        self.seadp_packet_order = packet_order

    def setPayload(self, payload):
        self.payload = payload

    def checksum(self, data):
        length = len(data)
        checksum = 0
        for i in range(0, length):
            checksum += int.from_bytes(data[i:i + 1], 'little', signed=False)
        checksum &= 0xffff
        checksum_hex = int2byte(checksum,16)
        return checksum_hex

    def fill_packet(self, slen):
        self.header_len = slen + len(self.tlv)
        print("SeaDP 长度：")
        print(self.header_len)
        self.header_checksum = self.sum_checksum()

    def sum_checksum(self):
        src_guid_hex = binascii.a2b_hex(self.src_guid)
        dst_guid_hex = binascii.a2b_hex(self.dst_guid)
        service_type_hex = binascii.a2b_hex(self.service_type)
        header_len_hex = binascii.a2b_hex(int2byte(self.header_len,8))
        other = src_guid_hex + dst_guid_hex + service_type_hex + header_len_hex
        return self.checksum(other)

    def check_checksum(self):
        if self.header_checksum == self.sum_checksum():
            return True
        else:
            return False


    def seadp2byte(self):
        #id首部 id_next_head_type, id_length, id_seanet_prot_pro, src_guid, dst_guid, src_port, dst_port, packet_type, cache_type, tran_type_res, chunk_total_len, packet_offset, packet_order
        id_next_head_type_hex = binascii.a2b_hex(self.id_next_head_type)
        id_length_hex = binascii.a2b_hex(self.id_length)
        id_seanet_prot_pro_hex = binascii.a2b_hex(self.id_seanet_prot_pro)
        src_guid_hex = binascii.a2b_hex(self.src_guid)
        dst_guid_hex = binascii.a2b_hex(self.dst_guid)
        id_head_hex = id_next_head_type_hex + id_length_hex + id_seanet_prot_pro_hex + src_guid_hex + dst_guid_hex
        #SeaDP首部
        src_port_hex = binascii.a2b_hex(self.seadp_src_port)
        dst_port_hex = binascii.a2b_hex(self.seadp_dst_port)
        packet_type_hex = binascii.a2b_hex(self.seadp_packet_type)
        cache_type_hex = binascii.a2b_hex(self.seadp_cache_type)
        tran_type_res_hex = binascii.a2b_hex(self.seadp_tran_type_res)
        chunk_total_len_hex = binascii.a2b_hex(self.seadp_chunk_total_len)
        packet_offset_hex =  binascii.a2b_hex(self.seadp_packet_offset)
        packet_order_hex = binascii.a2b_hex(self.seadp_packet_order)
        #SeaDP首部checksum
        other_hex =  src_port_hex + dst_port_hex + packet_type_hex + cache_type_hex + tran_type_res_hex + chunk_total_len_hex + packet_offset_hex + packet_order_hex
        self.header_checksum = self.checksum(other_hex)
        seadp_header_checksum_hex = binascii.a2b_hex(self.header_checksum)
        #hex_result =   service_type_hex + header_len_hex + header_checksum_hex + src_guid_hex + dst_guid_hex  + self.tlv + self.payload
        hex_result = id_head_hex + other_hex + seadp_header_checksum_hex + self.payload
        return hex_result

    #之前修改了seaDP2byte，下面函数需要根据字段结构进行更改
    def byte2SeaDP(self, data):
        self.src_guid = binascii.b2a_hex(data[0:16]).decode('utf-8')
        self.dst_guid = binascii.b2a_hex(data[16:32]).decode('utf-8')
        self.service_type = binascii.b2a_hex(data[32:33]).decode('utf-8')
        self.header_len = int(binascii.b2a_hex(data[33:34]), 16)
        self.header_checksum = binascii.b2a_hex(data[34:44]).decode('utf-8')
        self.tlv = data[44:self.header_len]
        self.payload = data[self.header_len:len(data)]

    def str2SeaDP(self,data):
        self.src_guid=data[:32]
        self.dst_guid=data[32:64]
        self.service_type=data[64:66]
        self.header_len = int(data[66:68],16)
        self.header_checksum = data[68:72]
        self.tlv = binascii.a2b_hex(data[72:self.header_len*2])
        self.payload = binascii.a2b_hex(data[self.header_len*2:len(data)*2])