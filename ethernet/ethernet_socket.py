from ethernet_frame import EthernetFrame
from raw_socket import RawSocket
from utils import get_local_mac, get_mac_addr_from_str, get_default_iface
from socket_logger import debug_log
import arp_packet
import ethernet_frame

HTYPE_ARP = 0x0806
PTYPE_IPV4 = 0x0800


class EthernetSocket:
    def __init__(self, src_ip, gateway_ip):
        network_device_name = get_default_iface()
        self.raw_socket = RawSocket(network_device_name)
        self.src_mac = get_local_mac()
        # temp dest mac address FF:FF:FF:FF:FF:FF
        # ARP can get the real gateway mac address by broadcast
        self.dest_mac = get_mac_addr_from_str("FF:FF:FF:FF:FF:FF")
        self.dest_mac = self._get_remote_mac(src_ip, self.src_mac, gateway_ip)
        self.raw_socket = RawSocket()

    def send(self, data, type_num=PTYPE_IPV4):
        # create an ethernet frame
        ethernet_frm = EthernetFrame(self.src_mac, self.dest_mac, type_num, data)
        self.raw_socket.send(ethernet_frame.assemble(ethernet_frm))

    def receive(self, type_num=PTYPE_IPV4):
        while True:
            recv_frame = ethernet_frame.dissemble(self.raw_socket.receive())
            # if the frame is the type of data we expect to receive
            if recv_frame.type_num == type_num:
                return recv_frame.data

    def _get_remote_mac(self, src_ip, src_mac, gate_ip):
        spa = src_ip
        sha = src_mac
        tpa = gate_ip
        tha = self.dest_mac

        sent_arp_pac = arp_packet.ARPPacket(sha, spa, tha, tpa)
        sent_arp_data = arp_packet.assemble(sent_arp_pac)
        debug_log("send arp request")
        self.send(sent_arp_data, type_num=HTYPE_ARP)

        recv_arp_data = self.receive(type_num=HTYPE_ARP)
        debug_log("receive arp response")
        recv_arp_pac = arp_packet.dissemble(recv_arp_data)
        return recv_arp_pac.sha
