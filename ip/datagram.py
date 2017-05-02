import socket
from struct import *
from utils import get_random_number, calculate_checksum
from socket_logger import error_log
from ctypes import create_string_buffer

# packer format
PACKER_FORMAT = "!BBHHHBBH4s4s"

# transform the full datagram string to an IPDatagram object
def dissemble(full_datagram):
    ip_datagram = IPDatagram()
    ip_header = unpack(PACKER_FORMAT, full_datagram[0:20])
    version_ihl = ip_header[0]
    ip_datagram.version = version_ihl >> 4
    ip_datagram.ihl = version_ihl & 0xF
    ip_datagram.type_of_service = ip_header[1]
    ip_datagram.total_length = ip_header[2]
    ip_datagram.id = ip_header[3]
    flags_fragment_offset = ip_header[4]
    flags = flags_fragment_offset >> 13
    ip_datagram.flag_reserved = (flags & 0b100) >> 2
    ip_datagram.flag_df = (flags & 0b010) >> 1
    ip_datagram.flag_mf = flags & 0b001
    ip_datagram.fragment_offset = flags_fragment_offset & 0x1fff
    ip_datagram.ttl = ip_header[5]
    ip_datagram.protocol = ip_header[6]
    ip_datagram.header_checksum = ip_header[7]
    src_addr = ip_header[8]
    ip_datagram.src_ip = socket.inet_ntoa(src_addr)
    dest_addr = ip_header[9]
    ip_datagram.dest_ip = socket.inet_ntoa(dest_addr)

    # very important! remove the ethernet padding at the frame end
    data_len = ip_datagram.total_length - ip_datagram.ihl * 4
    ip_datagram.data = full_datagram[ip_datagram.ihl * 4: ip_datagram.ihl * 4 + data_len]

    # calculate the checksum
    tmp_ip_header = _assemble_ip_header(ip_datagram, src_addr, dest_addr, version_ihl, flags_fragment_offset)
    # if the checksum field is correct, the result of calculation should be 0
    result = calculate_checksum(tmp_ip_header)
    if result != 0:
        error_log("wrong ip datagram checksum!")
        return None

    return ip_datagram


# transform the IPDatagram object to a string, which will then be sent by the ip socket
def assemble(ip_datagram):
    src_addr = socket.inet_aton(ip_datagram.src_ip)
    dest_addr = socket.inet_aton(ip_datagram.dest_ip)
    version_ihl = (ip_datagram.version << 4) + ip_datagram.ihl
    flags_fragment_offset = (ip_datagram.flag_reserved << 15) \
                            + (ip_datagram.flag_df << 14) \
                            + (ip_datagram.flag_mf << 13) \
                            + ip_datagram.fragment_offset
    # get a temporary header without checksum
    tmp_ip_header = _assemble_ip_header(ip_datagram, src_addr, dest_addr, version_ihl, flags_fragment_offset)
    # calculate the checksum of IP header and place the result in the checksum field
    real_checksum = calculate_checksum(tmp_ip_header)
    ip_datagram.header_checksum = real_checksum
    ip_header = _assemble_ip_header(ip_datagram, src_addr, dest_addr, version_ihl, flags_fragment_offset, True)
    return ip_header + ip_datagram.data


def _assemble_ip_header(ip_datagram, src_addr, dest_addr, version_ihl, flags_fragment_offset, final_checksum=False):
    ip_header_buf = create_string_buffer(calcsize(PACKER_FORMAT))
    pack_into(PACKER_FORMAT,
              ip_header_buf,
              0,
              version_ihl,
              ip_datagram.type_of_service,
              ip_datagram.total_length,
              ip_datagram.id,
              flags_fragment_offset,
              ip_datagram.ttl,
              ip_datagram.protocol,
              ip_datagram.header_checksum,
              src_addr,
              dest_addr)
    if final_checksum:
        pack_into("H", ip_header_buf, calcsize(PACKER_FORMAT[:8]), ip_datagram.header_checksum)
    return ip_header_buf.raw


class IPDatagram:
    def __init__(self, src_ip="", dest_ip="", data=""):
        '''
        src_ip          : source ip address
        dest_ip         : destination ip address
        data            : data to be sent
        version         : ip version, can be IPv4 or IPv6
        ihl             : header length
        type of service : default is 0
        total_length    : total length of the datagram
        id              : datagram id
        flag_reserved   : default is 0
        flag_df         : do not fragment flag
        flag_mf         : more fragments flag
        fragment_offset : used in fragmentation
        ttl             : time to live
        protocol        : transfer layer protocol
        header_checksum : checksum of the ip header
        '''
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.data = data
        self.version = 4
        self.ihl = 5
        self.type_of_service = 0
        self.total_length = calcsize(PACKER_FORMAT) + len(data)
        self.id = get_random_number(0, 65535)
        self.flag_reserved = 0
        self.flag_df = 1
        self.flag_mf = 0
        self.fragment_offset = 0
        self.ttl = 255
        self.protocol = socket.IPPROTO_TCP
        self.header_checksum = 0
