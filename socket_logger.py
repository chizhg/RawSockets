import logging

# logging.basicConfig(filename='raw_socket.log', level=logging.DEBUG)
# logging.basicConfig(level=logging.DEBUG)
logging.basicConfig(level=logging.ERROR)


def debug_log(message):
    logging.debug(message)


def error_log(message):
    logging.error(message)
