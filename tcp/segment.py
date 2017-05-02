import socket
from struct import *
from utils import get_random_number, calculate_checksum
from socket_logger import error_log

HEADER_PACK_FORMAT = "!HHLLBBHHH"
PSEUDO_HEADER_PACK_FORMAT = "!4s4sBBH"
PARTIAL_HEADER_PACK_FORMAT = "!HHLLBBH"


def dissemble(full_segment, src_ip, dest_ip):
    tcp_partial_header = unpack(PARTIAL_HEADER_PACK_FORMAT, full_segment[0:16])
    tcp_segment = TCPSegment()
    tcp_segment.src_port = tcp_partial_header[0]
    tcp_segment.dest_port = tcp_partial_header[1]
    tcp_segment.seq_num = tcp_partial_header[2]
    tcp_segment.ack_num = tcp_partial_header[3]
    offset_reserved = tcp_partial_header[4]
    tcp_segment.data_offset = offset_reserved >> 4
    flags = tcp_partial_header[5]
    tcp_segment.fin = flags & 0b00000001
    tcp_segment.syn = (flags & 0b00000010) >> 1
    tcp_segment.rst = (flags & 0b00000100) >> 2
    tcp_segment.psh = (flags & 0b00001000) >> 3
    tcp_segment.ack = (flags & 0b00010000) >> 4
    tcp_segment.urg = (flags & 0b00100000) >> 5
    tcp_segment.window_size = tcp_partial_header[6]
    tcp_segment.checksum = unpack("H", full_segment[16:18])[0]
    tcp_segment.urgent_pointer = unpack("!H", full_segment[18:20])[0]

    header_length = tcp_segment.data_offset * 4
    # header_length > 20 means it has options field
    if header_length > 20:
        tcp_segment.options = unpack("!L", full_segment[20: header_length])[0]

    # the part after header length is for tcp segment data
    tcp_segment.data = full_segment[header_length: ]
    tmp_tcp_header = _assemble_tmp_tcp_header(tcp_segment, offset_reserved, flags)
    expected_checksum = _calculate_segment_checksum(tmp_tcp_header, src_ip,
                                                   dest_ip, tcp_segment.data)
    if expected_checksum != tcp_segment.checksum:
        error_log("wrong tcp segment checksum, " + "expected: " + str(expected_checksum) + ", actual: " + str(tcp_segment.checksum))
        return None

    return tcp_segment


# transform a TCPSegment object to a string, which will then be sent by the socket
def assemble(tcp_segment):
    offset_reserved = (tcp_segment.data_offset << 4) + tcp_segment.reserved
    flags = tcp_segment.fin + (tcp_segment.syn << 1) + (tcp_segment.rst << 2) + (
        tcp_segment.psh << 3) + (
                tcp_segment.ack << 4) + (tcp_segment.urg << 5)

    tmp_tcp_header = _assemble_tmp_tcp_header(tcp_segment, offset_reserved,
                                              flags)
    tcp_checksum = _calculate_segment_checksum(tmp_tcp_header, tcp_segment.src_ip,
                                              tcp_segment.dest_ip,
                                              tcp_segment.data)

    # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
    tcp_header = pack(PARTIAL_HEADER_PACK_FORMAT,
                      tcp_segment.src_port,
                      tcp_segment.dest_port,
                      tcp_segment.seq_num,
                      tcp_segment.ack_num,
                      offset_reserved,
                      flags,
                      tcp_segment.window_size) + \
                 pack("H", tcp_checksum) + \
                 pack("!H", tcp_segment.urgent_pointer)
    return tcp_header + tcp_segment.data


# assemble the temp tcp header, which will be used to compute the checksum
def _assemble_tmp_tcp_header(tcp_segment, offset_reserved, flags):
    # checksum should be set to 0 when calculating the real checksum
    checksum = 0

    tmp_tcp_header = pack(HEADER_PACK_FORMAT,
                          tcp_segment.src_port,
                          tcp_segment.dest_port,
                          tcp_segment.seq_num,
                          tcp_segment.ack_num,
                          offset_reserved,
                          flags,
                          tcp_segment.window_size,
                          checksum,
                          tcp_segment.urgent_pointer)
    if tcp_segment.options != 0:
        options_pack = pack("!L", tcp_segment.options)
        tmp_tcp_header += options_pack
    return tmp_tcp_header


# calculate checksum for the given segment
def _calculate_segment_checksum(tmp_tcp_header, src_ip, dest_ip, data):
    pseudo_header = _assemble_pseudo_header(tmp_tcp_header, src_ip, dest_ip, len(data))
    checksum_base = pseudo_header + tmp_tcp_header + data
    tcp_checksum = calculate_checksum(checksum_base)
    return tcp_checksum


# assemble pseudo ip, which will then be used to calculate the checksum
def _assemble_pseudo_header(tmp_tcp_header, src_ip, dest_ip, data_len):
    # fields of pseudo header
    src_address = socket.inet_aton(src_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tmp_tcp_header) + data_len

    pseudo_header = pack(PSEUDO_HEADER_PACK_FORMAT,
                         src_address,
                         dest_address,
                         placeholder,
                         protocol,
                         tcp_length)
    return pseudo_header


class TCPSegment:
    def __init__(self, src_ip="", src_port=0, dest_ip="", dest_port=0, data=""):
        '''
        src_ip         :  source ip
        src_port       :  source port
        dest_ip        :  destination ip
        dest_port      :  destination port
        data           :  data to be sent
        seq_num        :  sequence number
        ack_num        :  acknowledge number
        data_offset    :  size of the TCP header
        reserverd      :  default is 0
        urg,
        ack,
        psh,
        rst,
        syn,
        fin            :  flags
        window_size    :  slide window size
        checksum       :  TCP checksum
        urgent_pointer :  default is 0
        options        :  optional, contains some special information
        '''
        self.src_ip = src_ip
        self.src_port = src_port
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.data = data
        self.seq_num = get_random_number()
        self.ack_num = 0
        self.data_offset = 5
        self.reserved = 0
        self.urg = 0
        self.ack = 0
        self.psh = 0
        self.rst = 0
        self.syn = 0
        self.fin = 0
        self.window_size = 29200
        self.checksum = 0
        self.urgent_pointer = 0
        self.options = 0
        self.data = data


class TCPSegmentFactory:
    def __init__(self, src_ip, src_port, dest_ip, dest_port):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dest_ip = dest_ip
        self.dest_port = dest_port

    def create_syn(self):
        syn_segment = TCPSegment(self.src_ip, self.src_port, self.dest_ip, self.dest_port)
        syn_segment.syn = 1
        return syn_segment

    def create_ack(self, seq_num, ack_num):
        ack_segment = TCPSegment(self.src_ip, self.src_port, self.dest_ip, self.dest_port)
        ack_segment.ack = 1
        ack_segment.seq_num = seq_num
        ack_segment.ack_num = ack_num
        return ack_segment

    def create_psh_ack(self, seq_num, ack_num, data):
        psh_ack_segment = TCPSegment(self.src_ip, self.src_port, self.dest_ip, self.dest_port)
        psh_ack_segment.psh = 1
        psh_ack_segment.ack = 1
        psh_ack_segment.data = data
        psh_ack_segment.seq_num = seq_num
        psh_ack_segment.ack_num = ack_num
        return psh_ack_segment

    def create_fin_ack(self, seq_num, ack_num):
        ack_segment = TCPSegment(self.src_ip, self.src_port, self.dest_ip, self.dest_port)
        ack_segment.fin = 1
        ack_segment.ack = 1
        ack_segment.seq_num = seq_num
        ack_segment.ack_num = ack_num
        return ack_segment

    def create_fin(self, seq_num, ack_num):
        fin_segment = TCPSegment(self.src_ip, self.src_port, self.dest_ip, self.dest_port)
        fin_segment.fin = 1
        fin_segment.seq_num = seq_num
        fin_segment.ack_num = ack_num
        return fin_segment
禾