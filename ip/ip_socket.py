from raw_socket import RawSocket
from datagram import IPDatagram, assemble, dissemble
from socket_logger import debug_log, error_log
from utils import timeout, TimeoutError, get_gateway_ip
from ethernet.ethernet_socket import EthernetSocket
import sys

MAX_TIMEOUT = 180

class IPSocket:
    def __init__(self, src_ip, dest_ip):
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        gateway_ip = get_gateway_ip()
        self.eth_socket = EthernetSocket(src_ip, gateway_ip)

    def send(self, data):
        ip_datagram = IPDatagram(self.src_ip, self.dest_ip, data)
        # pack the IP datagram in Ethernet Frame and use ethernet socket to send
        self.eth_socket.send(assemble(ip_datagram))

    def receive(self):
        try:
            ip_datagram = self._receive_datagram()
            return ip_datagram.data
        except TimeoutError:
            error_log("no datagram received for a long time, dead connection!")
            sys.exit(-1)

    @timeout(MAX_TIMEOUT, "timeout happens when ip receives datagram")
    def _receive_datagram(self):
        while True:
            ip_datagram = dissemble(self.eth_socket.receive())
            if ip_datagram is not None:
                debug_log(
                   "receive datagram from " + ip_datagram.src_ip + " to " + ip_datagram.dest_ip)
                if ip_datagram.src_ip == self.dest_ip and ip_datagram.dest_ip == self.src_ip:
                    return ip_datagram
