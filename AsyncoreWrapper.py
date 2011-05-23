import socket, asyncore

class AsyncoreUdp(asyncore.dispatcher):
    """
    Wrapper around asyncore for UDP to deal with writable() busy waiting.
    Creates a queue for outgoing datagrams.
    The user should push a datagram with associated
    IP and port to that list, and the object will send
    these accordingly.

    Based on http://docs.ganeti.org/ganeti/2.1/api/ganeti.daemon.AsyncUDPSocket-class.html

    @author Yiannis Yiakoumis
    @date April 2011
    """
    def __init__(self):
        '''Initialize a list for outgoing datagrams.'''
        asyncore.dispatcher.__init__(self)
        self._output_queue = []

    def writable(self):
        '''Register for select only when there are packets
        to send.'''
        return (len(self._output_queue) > 0)

    def handle_write(self):
        '''Sends the next packet from the queue.'''
        if not self._output_queue:
            logging.error("AsyncoreUdp write on an empty queue")
            return
        (ip,port,payload) = self._output_queue[0]
        self.sendto(payload,0,(ip,port))
        self._output_queue.pop(0)

    def enqueue_send(self,ip,port,payload):
        '''Adds an ip,port,payload tuple to the queue.'''
        self._output_queue.append((ip,port,payload))

class AsyncoreTcp(asyncore.dispatcher):
    """
    Wrapper around asyncore for TCP to deal with writable() busy waiting.
    """
    def __init__(self, socket = None):
        '''Initialize a buffer that keeps the outgoing stream.'''
        asyncore.dispatcher.__init__(self,socket)
        self.write_buffer = ''

    def writable(self):
        '''Register for select only when there are pending data.'''
        is_writable = (len(self.write_buffer) > 0)
        return is_writable

    def handle_write(self):
        '''Send as much as you can.'''
        sent = self.send(self.write_buffer)
        self.write_buffer = self.write_buffer[sent:]
        return

    def enqueue_send(self,data):
        '''Add data to the outgoing buffer.'''
        self.write_buffer = self.write_buffer + data
