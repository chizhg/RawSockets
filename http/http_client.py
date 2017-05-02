from http.http_content import build_http_content, parse_http_response
from tcp.tcp_socket import TCPSocket
from socket_logger import error_log
import sys


def do_get(url):
    host, http_data = build_http_content(url)
    tcp_socket = TCPSocket(host)
    tcp_socket.send(http_data)
    data = tcp_socket.receive(None)
    if not tcp_socket.close():
        debug_log("failed to close the socket")
    status_code, http_body = parse_http_response(data)
    if status_code != "200":
        error_log("status code of the response is not 200, exit the program!")
        sys.exit(-1)
    return http_body


# to be implemented
def do_post(url, data):
    return ""
