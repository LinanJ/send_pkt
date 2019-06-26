import socket
from icn_head import ICNPacket
from seadp_head import SeaDPPacket  
import binascii
from util import int2byte
import sys


class GnrsClient():
       
    def register(self, src_eid, dst_eid, eid, na, stype, tlv_tag, tlv_length, tlv_value, slen):
        icn_packet = ICNPacket()
        icn_packet.setHeader(src_eid, dst_eid, stype)
        #tlv = binascii.a2b_hex(tlv)
        cmd_type = binascii.a2b_hex("88")
        eid_hex = binascii.a2b_hex(eid)
        na_hex=binascii.a2b_hex(na)

        icn_packet.setTLV(tlv_tag, tlv_length, tlv_value)
        icn_packet.setPayload(cmd_type + eid_hex+na_hex)
        icn_packet.fill_packet(slen)
        pkt = icn_packet.icn2byte()
        return pkt

    def seadp_register(self,id_next_head_type, id_length, id_seanet_prot_pro, src_guid,
                       dst_guid, src_port, dst_port, packet_type, cache_type, tran_type_res, chunk_total_len, packet_offset, packet_order, payload):
        seadp_packet = SeaDPPacket()
        seadp_packet.setHeader(id_next_head_type, id_length, id_seanet_prot_pro, src_guid, dst_guid, src_port, dst_port, packet_type, cache_type, tran_type_res, chunk_total_len, packet_offset, packet_order)
        #tlv = binascii.a2b_hex(tlv)
        payload_hex = binascii.a2b_hex(payload)

        seadp_packet.setPayload(payload_hex)
        pkt = seadp_packet.seadp2byte()
        return pkt