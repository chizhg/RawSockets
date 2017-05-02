import commands
import socket
import random
import struct
import signal
import fcntl
import functools
import sys
from socket_logger import error_log


def get_local_ip():
    ip_line = commands.getoutput("/sbin/ifconfig").split("\n")[1].split()[1]
    ip = ip_line if ip_line.find(':') == -1 else ip_line[ip_line.find(':') + 1:]
    return ip


def get_default_iface():
    default_route_entry = _get_default_route_entry()
    return default_route_entry.split()[0]


def get_gateway_ip():
    # get gateway IP address from route table
    gateway_ip = int(_get_default_route_entry().split()[2], 16)
    return socket.inet_ntoa(struct.pack("=l", gateway_ip))


def _get_default_route_entry():
    route_file = "/proc/net/route"
    with open(route_file) as f:
        for route_entry in f.readlines():
            route_entry = route_entry.strip()
            columns = route_entry.split()
            dest = columns[1]
            flags = columns[3]
            if dest != "00000000" or not int(flags, 16) & 2:
                continue
            return route_entry
    error_log("cannot find default route entry in the route table, exit the program")
    sys.exit(-1)


def get_local_mac(device='eth0'):
    # http://stackoverflow.com/questions/159137/getting-mac-address
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', device[:15]))[18:24]


def get_remote_ip_by_host(host):
    return socket.gethostbyname(host)


def get_random_number(lower_bound=0, upper_bound=1000):
    return random.randint(lower_bound, upper_bound)


# calculate checksum for the given data
# http://en.wikipedia.org/wiki/IPv4_header_checksum
def calculate_checksum(data):
    if len(data) % 2 == 1:
        data += struct.pack('B', 0)

    csum = 0
    # loop taking 2 characters at a time
    for i in range(0, len(data), 2):
        w = ord(data[i]) + (ord(data[i + 1]) << 8)
        csum += w

    csum = (csum >> 16) + (csum & 0xffff)
    csum += (csum >> 16)

    # complement and mask to 4 byte short
    csum = ~csum & 0xffff

    return csum


def get_free_port():
    # get free port from creating a new socket, and close it
    sock = socket.socket()
    sock.bind(('', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def get_mac_addr_from_str(addr):
    # convert a string as a MAC address to a packed data
    hexs = map(lambda x: int(x, 16), addr.split(':'))
    return struct.pack('!6B', hexs[0], hexs[1], hexs[2], hexs[3], hexs[4],
                       hexs[5])


class TimeoutError(Exception):
    pass

# timeout decorator
def timeout(seconds, error_msg="timeout happens when calling this function"):
    def decorator(func):
        def _handle_timeout(signum, frame):
            raise TimeoutError(error_msg)

        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, _handle_timeout)
            signal.alarm(seconds)
            try:
                func_result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return func_result

        return functools.wraps(func)(wrapper)

    return decorator
