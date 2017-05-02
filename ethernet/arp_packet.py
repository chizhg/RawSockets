from struct import pack, unpack
import socket

ARP_FRAME_FORMAT = '!HHBBH6s4s6s4s'
HEADER_LENGTH = 28
# hardware type, default is Ethernet
HTYPE_ETHERNET = 0x0001
# protocol type, default is IPV4
PTYPE_IPV4 = 0x0800
# hardware length, Ethernet addresses size is 6
HLEN_ETHERNET = 0x0006
# protocol length, IPv4 address size is 4
PLEN_IPV4 = 0x0004
# operation type, 1 for request, 2 for reply
OPTR_REQUEST = 1
OPTR_REPLY = 2


def assemble(arp_packet):
    arp_packet = pack(ARP_FRAME_FORMAT, arp_packet.htype, arp_packet.ptype,
                      arp_packet.hlen, arp_packet.plen, arp_packet.optr,
                      arp_packet.sha, socket.inet_aton(arp_packet.spa), arp_packet.tha, socket.inet_aton(arp_packet.tpa))
    return arp_packet


def dissemble(full_packet):
    arp_packet = ARPPacket()
    header = unpack(ARP_FRAME_FORMAT, full_packet[0:HEADER_LENGTH])
    arp_packet.htype = header[0]
    arp_packet.ptype = header[1]
    arp_packet.hlen = header[2]
    arp_packet.plen = header[3]
    arp_packet.optr = header[4]
    arp_packet.sha = header[5]
    arp_packet.spa = socket.inet_ntoa(header[6])
    arp_packet.tha = header[7]
    arp_packet.tpa = socket.inet_ntoa(header[8])
    return arp_packet


class ARPPacket:
    def __init__(self, sha='', spa='', tha='', tpa='', optr=OPTR_REQUEST):
        '''
        htype : hardware type
        ptype : protocol type
        hlen  : hardware address length
        plen  : protocal address length
        optr  : operation
        sha   : sender hardware address
        tha   : target hardware address
        spa   : sender protocol address
        tpa   : target protocol address
        '''
        self.htype = HTYPE_ETHERNET
        self.ptype = PTYPE_IPV4
        self.hlen = HLEN_ETHERNET
        self.plen = PLEN_IPV4
        self.optr = optr
        self.sha = sha
        self.spa = spa
        self.tha = tha
        self.tpa = tpa
