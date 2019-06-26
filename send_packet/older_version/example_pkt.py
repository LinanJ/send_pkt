import socket
import struct
#from gnrs_client import *
import gnrs_client
import logging.config
import sys


'''
add by jingln
function : send a seanet packet in L4,pkt formate IPV4+SEANET 
input:src_ip, dst_ip, these are src and dst host's ip
* please use python3.6 run
e.g.：
    # cd/PNPL/pnpl
    # scripts/multi/mininet
    # mininet> xterm h1
    # h1>python3.6 example_pkt
    # src_ip :10.0.0.1
    # dst_ip :10.0.0.2
    
'''
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


    def set_para(self, seanet_type, src_eid, dst_eid, tlv_tag, tlv_length, tlv_value, slen):
        self.seanet_type = seanet_type
        self.src_eid = src_eid
        self.dst_eid = dst_eid
        self.tlv_tag = tlv_tag
        self.tlv_length = tlv_length
        self.tlv_value = tlv_value
        self.slen = slen


    def ping_mobility(self, src_ip, dst_ip):     
        na_type = int(input("na: 0a000001- 1\n 0a000002- 2\n 0a000003- 3\n 0a000004- 4\n:"))
        if na_type == 1:
            na = "0a000001"
        elif na_type == 2:
            na = "0a000002"
        elif na_type == 3:
            na = "0a000003"
        elif na_type == 4:
            na = "0a000004"    
        else:
            print("wrong type!\n")
            sys.exit(1)
        tag_mobility_thing = "0300"
        len_mobility_thing = "0024"
        data = "0300" + "0024" + self.dst_eid + na
        self.client.send_udp(data, dst_ip, 9000)
        

    def ping_multicast(self, src_ip, dst_ip):
        data = "99887766"
        self.client.send_udp(data, dst_ip, 1111)

    def ping_seanet(self, src_ip, dst_ip):
        s=socket.socket(socket.AF_INET,socket.SOCK_RAW,255)
        s.setsockopt(0, socket.IP_HDRINCL, 1)
    # now start constructing the packet
        
        source_ip = src_ip
        dest_ip = dst_ip
     
    # ip header fields
        ihl = 5  #shaorted IP pkt
        version = 4  #ipv4
        tos = 0  #no special priority
        tot_len = 56 # total length
        id = 0
        frag_off = 0
        ttl = 255
        protocol = 153 #protocol number
        check = 0  
        saddr =socket.inet_aton ( source_ip )  #Spoof the source ip address if you want to
        daddr = socket.inet_aton ( dest_ip )
        ihl_version = (version << 4) + ihl

        # the ! in the pack format string means network order
        # first parameter is formate
        # B is 8, H is 16
        ip_header = struct.pack('!BBHHHBBH4s4s', ihl_version, tos, tot_len, id,
         frag_off, ttl, protocol, check, saddr, daddr)
  
        udp_header = struct.pack('!4s4s', saddr, daddr)
        
        eid = "11111000000000000000000000022222"
        na  = "11223344"
        udp_fill = "1234567890123456"
        result = self.client.register(self.src_eid, self.dst_eid, eid, na, self.seanet_type, self.tlv_tag, self.tlv_length, self.tlv_value, self.slen)
        #print(self.src_eid, self.dst_eid, eid, na, self.seanet_type, self.tlv_tag, self.tlv_length, self.tlv_value)
        #packet = ip_header + udp_header +result
        packet = ip_header  + result
        s.sendto(packet,(dst_ip,99))
        logging.info(result)

#the src_ip and dst_ip should be the host ip
if __name__=='__main__':

    pkt = PktGen()

    service_type = int(input("select test type: \n \
    1 - multicast aggregation h2 is source !\n \
    2 - host add multicast \n \
    3 - mobility event\n \
    4 - mobility data\n"))

    if service_type == 1:
        src_ip = "10.0.0.2"
        dst_ip = "10.0.100.3"
        seanet_type = "08"
        tlv_tag = "0002"
        tlv_length = "0014"
        tlv_value = "ddddd0000000000000000000000fffff" #h1-EID
        src_eid = "22222000000000000000000000044444" #multi src eid
        dst_eid = "000000000000000000000000e0010002"
        pkt.set_para(seanet_type, src_eid, dst_eid, tlv_tag, tlv_length, tlv_value,"")
        pkt.ping_seanet(src_ip, dst_ip)

    elif service_type == 2:
        src_ip_type = int(input("select host ip to join multicast:\n \
            1. 10.0.0.1\n 2. 10.0.0.3\n"))
        if src_ip_type == 1:
            src_ip = "10.0.0.1"
        elif src_ip_type == 2:
            src_ip = "10.0.0.3"
        else:
            src_ip = "10.0.0.1"
        dst_ip = "10.0.100.3"
        seanet_type = "08"
        tlv_tag = "0001"
        tlv_length = "0008"
        tlv_value = "00000001" 
        src_eid = "c11e70000000000000000000000c11e7" #h1-EID
        dst_eid = "000000000000000000000000e0010002"
        pkt.set_para(seanet_type, src_eid, dst_eid, tlv_tag, tlv_length, tlv_value,"")
        pkt.ping_seanet(src_ip, dst_ip)

    elif service_type == 3:
        src_ip_type = int(input("src_ip: 10.0.0.1- 1\n 10.0.0.2- 2\n 10.0.0.3- 3\n 10.0.0.4- 4\n: 5-127\n"))
        if src_ip_type == 1:
            src_ip = "10.0.0.1"
        elif src_ip_type == 2:
            src_ip = "10.0.0.2"
        elif src_ip_type == 3:
            src_ip = "10.0.0.3"
        elif src_ip_type == 4:
            src_ip = "10.0.0.4"
        elif src_ip_type == 5:
            src_ip = "127.0.0.1"    
        else:
            print("wrong type!\n")
            sys.exit(1)

        dst_ip_type = int(input("dst_ip: 10.0.100.1- 1\n 10.0.100.2- 2\n 10.0.100.3- 3\n 10.0.100.4- 4\n:"))
        if dst_ip_type == 1:
            dst_ip = "10.0.100.1"
            slen = 1
        elif dst_ip_type == 2:
            dst_ip = "10.0.100.2"
            slen = 2
        elif dst_ip_type == 3:
            dst_ip = "10.0.100.3"
        elif dst_ip_type == 4:
            dst_ip = "10.0.100.4"
        elif dst_ip_type == 5:
            dst_ip = "127.0.0.1"
        else:
            print("wrong type!\n")
            sys.exit(1)
        dst_eid = "00000000000000000000000000000001" #h1-EID
        pkt.set_para("", "", dst_eid, "", "", "",slen)
        pkt.ping_mobility(src_ip, dst_ip)

    elif service_type == 4:
        src_ip_type = int(input("src_ip: 10.0.0.1- 1\n 10.0.0.2- 2\n 10.0.0.3- 3\n 10.0.0.4- 4\n 10.0.0.5- 5\n:"))
        if src_ip_type == 1:
            src_ip = "10.0.0.1"
        elif src_ip_type == 2:
            src_ip = "10.0.0.2"
        elif src_ip_type == 3:
            src_ip = "10.0.0.3"
        elif src_ip_type == 4:
            src_ip = "10.0.0.4"
        elif src_ip_type == 5:
            src_ip = "10.0.0.5"      
        else:
            print("wrong type!\n")
            sys.exit(1)

        dst_ip_type = int(input("dst_ip: 10.0.0.1- 1\n 10.0.0.2- 2\n 10.0.0.3- 3\n 10.0.0.4- 4\n 10.0.0.5- 5\n:"))
        if dst_ip_type == 1:
            dst_ip = "10.0.0.1"
            slen = 1
        elif dst_ip_type == 2:
            dst_ip = "10.0.0.2"
            slen = 2
        elif dst_ip_type == 3:
            dst_ip = "10.0.0.3"
        elif dst_ip_type == 4:
            dst_ip = "10.0.0.4"
        elif dst_ip_type == 5:
            dst_ip = "10.0.0.5"
        else:
            print("wrong type!\n")
            sys.exit(1)

        seanet_type = "02"
        src_eid = "00000000000000000000000000000003" #h1-EID
        dst_eid = "00000000000000000000000000000001" #h2-EID
        pkt.set_para(seanet_type, src_eid, dst_eid, "", "", "", slen)
        pkt.ping_seanet(src_ip, dst_ip)

    else:
        print ("wrong type!\n")
        sys.exit(1)
