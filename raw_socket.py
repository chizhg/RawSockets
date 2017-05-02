import sys
from utils import *
from socket_logger import *


class RawSocket:
    def __init__(self, device):
        try:
            self.raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            # the defalut device will be eth0
            self.device = device
            self.raw_socket.bind((device, socket.SOCK_RAW))
        except socket.error, msg:
            print 'Socket could not be created. Error Code : ' + str(
                msg[0]) + ' Message ' + msg[1]
            sys.exit()

    def send(self, data):
        self.raw_socket.send(data)

    def receive(self, buffer_size=65536):
        return self.raw_socket.recvfrom(buffer_size)[0]
