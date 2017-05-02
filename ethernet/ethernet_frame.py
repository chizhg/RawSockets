from struct import pack, unpack

ETHERNET_FRAME_FORMAT = "!6s6sH"
HEADER_LENGTH = 14
# MIN_FRAME_SIZE = 64


def assemble(ethernet_frame):
    header = pack(ETHERNET_FRAME_FORMAT, ethernet_frame.dest_mac, ethernet_frame.src_mac, ethernet_frame.type_num)

    full_frame = header + ethernet_frame.data
    return full_frame


def dissemble(full_frame):
    ethernet_frame = EthernetFrame()
    header = unpack(ETHERNET_FRAME_FORMAT, full_frame[0:HEADER_LENGTH])
    ethernet_frame.src_mac = header[0]
    ethernet_frame.dest_mac = header[1]
    ethernet_frame.type_num = header[2]
    ethernet_frame.data = full_frame[HEADER_LENGTH:]
    return ethernet_frame


class EthernetFrame:
    def __init__(self, src_mac="", dest_mac="", type_num=0, data=""):
        '''
        src_mac  : source MAC address
        dest_num : destination MAC address
        type_num : the type number of frame
        data     : the data in the frame
        '''
        self.src_mac = src_mac
        self.dest_mac = dest_mac
        self.type_num = type_num
        self.data = data
