from socket_logger import error_log
import sys

CRLF = "\r\n"
URL_PROTOCOL = "http://"
DEFAULT_PATH = "/"
SPACE = " "
HEADER_END_MARK = CRLF * 2


def build_http_content(url):
    host, path = _parse_host_path(url)
    http_data = _build_first_line(path) + CRLF + _build_http_header_lines(host) + CRLF
    return host, http_data


def _build_first_line(path, method="GET", version="HTTP/1.0"):
    first_line = method.upper() + SPACE + path + SPACE + version
    return first_line


def _build_http_header_lines(host):
    header_content = ""
    header_content += ("Host: " + host)
    header_content += CRLF
    # header_content += "Connection: keep-alive"
    # header_content += CRLF
    return header_content


def _parse_host_path(url):
    if url.find(URL_PROTOCOL) != -1:
        url = url[(len(URL_PROTOCOL)):]

    # split host and path if the url contains /
    if url.find("/") != -1:
        host = url[0: url.find("/")]
        path = url[url.find("/"):]
    # otherwise host is the whole url, and path is the DEFAULT_PATH
    else:
        host = url
        path = DEFAULT_PATH

    return host, path


def parse_http_response(http_response):
    try:
        first_line = http_response[0: http_response.find(CRLF)]
        status_code = first_line.split(" ")[1]

        body_start_index = http_response.index(HEADER_END_MARK) + len(HEADER_END_MARK)
        body = http_response[body_start_index: ]

        return status_code, body
    except:
        error_log("fail to parse due to the invalid http response format!")
        sys.exit(-1)
