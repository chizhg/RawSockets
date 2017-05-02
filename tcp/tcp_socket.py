import sys
from utils import *
from segment import TCPSegmentFactory, assemble, dissemble
from ip.ip_socket import IPSocket
from socket_logger import debug_log, error_log
from io import BytesIO
from collections import deque, OrderedDict

MSS = 1460
MAX_CWND = 1000
MAX_TIMEOUT = 60


class TCPSocket:
    def __init__(self, host):
        # init source ip, destination ip, source port and destination port
        self.src_ip = get_local_ip()
        self.dest_ip = get_remote_ip_by_host(host)
        self.src_port = get_free_port()
        self.dest_port = 80
        # create an ip socket
        self.ip_socket = IPSocket(self.src_ip, self.dest_ip)
        # a segment factory, used to create segments
        self.segment_factory = TCPSegmentFactory(self.src_ip, self.src_port,
                                                 self.dest_ip, self.dest_port)
        # save received ordered data into the data holder, from which the application layer can read
        self.data_holder = BytesIO()
        # initial sequence number and acknowledge number should be 0
        self.seq_num = 0
        self.ack_num = 0

        # initial advertised window size
        self.awnd = 0
        # initial congestion window size
        self.cwnd = 1

        self.unacked_segments = OrderedDict()
        self.sender_queue = deque()

        self.connection_closed = False

    def send(self, data):
        # connect to the server with three-way handshake
        self._connect()

        # partition data if it cannot be sent within one segment
        self._partition_data(data)

        # send all segments in queue until all have been acked
        while len(self.sender_queue) != 0:
            self._send_data_in_queue()
            self._receive_acks_for_sent()
            # if there are segments that receive no ack, set the congestion window to 1
            if len(self.unacked_segments) != 0:
                self.cwnd = 1
                # reappend unacked_segments into the sender queue
                for unacked_seq_num, data_segment in self.unacked_segments.items():
                    self.sender_queue.appendleft(data_segment)

        self._receive_data_and_send_ack()
        # after receiving all data, set the pointer to the start
        self.data_holder.seek(0)

    # three-way handshake
    def _connect(self):
        debug_log("start three-way handshake")
        syn_segment = self.segment_factory.create_syn()
        self.seq_num = syn_segment.seq_num
        debug_log("send syn to server")

        # send syn to the server, resend if timeout
        self._send_segment(syn_segment)
        try:
            ack_syn_segment = self._receive_ack(1, 0)
        except TimeoutError:
            self._send_segment(syn_segment)
            try:
                ack_syn_segment = self._receive_ack(1, 0)
            except TimeoutError:
                # exit the program if still timeout
                sys.exit(-1)
                error_log("failed to create a TCP connection")

        debug_log("receive ack syn from server")
        # add 1 to the sequence number
        self.seq_num += 1
        # set the ack number
        self.ack_num = ack_syn_segment.seq_num + 1
        ack_segment = self.segment_factory.create_ack(self.seq_num,
                                                      self.ack_num)
        self._send_segment(ack_segment)
        debug_log("send ack to server")
        debug_log("complete three-way handshake")

    # partition data if it cannot be sent in a single segment
    def _partition_data(self, data):
        seg_seq_num = self.seq_num
        total_len = len(data)
        remain_len = total_len
        start_index = 0
        while remain_len > MSS:
            partitioned_data = data[start_index: start_index + MSS]
            debug_log("partition data: " + partitioned_data + ", seq_num: " + str(seg_seq_num))
            partitioned_data_seg = self.segment_factory.create_psh_ack(seg_seq_num, self.ack_num, partitioned_data)
            seg_seq_num += MSS
            start_index += MSS
            remain_len -= MSS
            # add the segment into the sender queue
            self.sender_queue.append(partitioned_data_seg)
        # add the last segment
        last_data = data[start_index: total_len]
        last_data_seg = self.segment_factory.create_psh_ack(seg_seq_num, self.ack_num, last_data)
        self.sender_queue.append(last_data_seg)

    # send the segments in the queue (the max number of segments that can be sent should be restricted by the window size)
    def _send_data_in_queue(self):
        # window size should be min(cwnd, awnd)
        wnd_size = min(self.cwnd * MSS, self.awnd)
        while wnd_size > 0 and len(self.sender_queue) > 0:
            data_segment = self.sender_queue.popleft()
            if len(data_segment.data) < wnd_size:
                debug_log("send request data to the server, sequence number: " + str(self.seq_num))
                self._send_segment(data_segment)
                expected_ack_num = self.seq_num + len(data_segment.data)
                self.unacked_segments[expected_ack_num] = data_segment
                wnd_size -= len(data_segment.data)
            else:
                self.sender_queue.appendleft(data_segment)
                break

    # receive the acks for all sent segments
    def _receive_acks_for_sent(self):
        for i in range(len(self.unacked_segments)):
            try:
                ack_seg = self._receive_ack(0, 0)
                # receive a new ack for one of the segments
                if ack_seg.ack_num in self.unacked_segments:
                    acked_segment = self.unacked_segments[ack_seg.ack_num]
                    if ack_seg.ack_num - self.seq_num == len(acked_segment.data):
                        self.seq_num += len(acked_segment.data)
                    # can safely remove it now
                    del self.unacked_segments[ack_seg.ack_num]
            except TimeoutError:
                return

    # when trying to receive ack, throw a timeout error if no ack received for 60 seconds
    @timeout(MAX_TIMEOUT, "timeout happends when tcp receives ack")
    def _receive_ack(self, syn_flag, fin_flag):
        while True:
            received_segment = self._receive_segment()
            if received_segment.syn == syn_flag and received_segment.fin == fin_flag:
                break
        # after receiving an ack, add 1 to the congestion window size if it's less than 1000
        if self.cwnd < MAX_CWND:
            self.cwnd += 1
        return received_segment

    # receive data from the server and send ack back
    def _receive_data_and_send_ack(self):
        init_data_index = self.ack_num
        unordered_data = dict()
        while True:
            segment = self._receive_segment()
            data = segment.data
            segment_index = segment.seq_num - init_data_index
            expected_index = self.ack_num - init_data_index
            # if the server sends fin and all data before has been received, break the auto ack mode
            if segment.fin == 1 and segment_index == expected_index:
                if len(data) != 0:
                    self._handle_ordered_data(data)
                # ack to fin
                self.ack_num += 1
                fin_ack_segment = self.segment_factory.create_fin_ack(
                    self.seq_num,
                    self.ack_num)
                self._send_segment(fin_ack_segment)
                debug_log("ack to fin")
                if self._receive_segment().ack == 1:
                    debug_log("successfully close the connection")
                    self.connection_closed = True
                    break

            # duplicate segment, drop it and ack (the ack number should be correct)
            if segment_index < expected_index:
                debug_log("get duplicate segment")
                ack_segment = self.segment_factory.create_ack(self.seq_num,
                                                              segment_index + init_data_index)
                self._send_segment(ack_segment)
                continue
            # new ordered segment (handle it and all cached unordered data)
            elif segment_index == expected_index:
                debug_log("get ordered segment")
                self._handle_ordered_data(data)
                self._handle_unordered_data(unordered_data)
            # unordered data, cache it
            else:
                debug_log("get unordered segment")
                unordered_data[segment_index] = segment.data
            ack_segment = self.segment_factory.create_ack(self.seq_num,
                                                          self.ack_num)
            self._send_segment(ack_segment)

    # handle all cached unordered data
    def _handle_unordered_data(self, unordered_data):
        for key in sorted(unordered_data):
            # if all data before it has been acked, handle it as an ordered data
            if key == self.ack_num:
                data = unordered_data[key]
                self._handle_ordered_data(data)
            # all data after it should also be unordered, so break directly
            elif key > self.data_holder.tell():
                break
            # duplicate data, delete
            else:
                del unordered_data[key]

    # handle ordered data
    def _handle_ordered_data(self, ordered_data):
        self.data_holder.write(ordered_data)
        self.ack_num += len(ordered_data)

    def receive(self, bufsize=4096):
        return self.data_holder.read(bufsize)

    # close the connection
    def close(self):
        if not self.connection_closed:
            fin_segment = self.segment_factory.create_fin(self.seq_num,
                                                          self.ack_num)
            # send fin to the server, resend if timeout
            self._send_segment(fin_segment)
            try:
                ack_fin_segment = self._receive_ack(0, 1)
            except TimeoutError:
                self._send_segment(fin_segment)
                try:
                    ack_fin_segment = self._receive_ack(0, 1)
                except TimeoutError:
                    # return False if still timeout
                    return False

                debug_log("receive ack fin from server")
                self.seq_num += 1
                self.ack_num += 1
                ack_segment = self.segment_factory.create_ack(self.seq_num,
                                                              self.ack_num)
                self._send_segment(ack_segment)
                debug_log("send ack to server")
                debug_log("complete connection teardown")

        return True

    def _send_segment(self, segment):
        self.ip_socket.send(assemble(segment))

    def _receive_segment(self):
        while True:
            tcp_segment = dissemble(self.ip_socket.receive(), self.dest_ip,
                                    self.src_ip)
            if tcp_segment is not None and tcp_segment.src_port == self.dest_port \
                    and tcp_segment.dest_port == self.src_port:
                # set advertised window size whenever receiving a new segment
                self.awnd = tcp_segment.window_size
                return tcp_segment
