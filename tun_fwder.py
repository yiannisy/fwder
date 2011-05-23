#!/usr/bin/python

import socket
import asyncore
import struct
import logging
import sys
import random

from AsyncoreWrapper import AsyncoreTcp

DEFAULT_LOCAL_HOST="127.0.0.1"
DEFAULT_LOCAL_PORT=9002

LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
RECV_FULL_SIZE = 32768

TUNNEL_TOR = 1

bridges = [("88.198.39.7",563), ("173.255.213.10",110), ("99.20.3.173",443)]
fwder = ("127.0.0.1",9999)

class TunnelSetupMsg(object):
    '''
    Header for tunnel setup on forwarder.
    '''
    def __init__(self, host, port, type):
        self.host = socket.inet_aton(host)
        self.port = port
        self.type = type
        
    def pack(self):
        return ''.join((self.host, struct.pack('!HH',self.port, self.type)))
    
    @staticmethod
    def unpack(body):
        host = struct.unpack_from('!I', body, offset = 0)[0]
        port = struct.unpack_from('!H', body, offset = 4)[0]
        type = struct.unpack_from('!H', body, offset = 6)[0]
        return TunnelSetupMsg(hos, port, type)                                    

class ForwarderHandler(AsyncoreTcp):
    def __init__(self, tor_client):
        AsyncoreTcp.__init__(self)
        self.tor_client = tor_client
        self.fwd_addr = fwder
        try:
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
            self.connect(self.fwd_addr)
        except socket.error, msg:
            logger.error("cannot connect to forwarder...(%s)" % msg)
            self.teardown()
            # sys.exit(0)
        # pickup a random bridge from the ones we have.
        bridge = bridges[random.randint(0,len(bridges) - 1)]
        self.enqueue_send(TunnelSetupMsg(bridge[0],bridge[1], TUNNEL_TOR).pack())

    def handle_read(self):
        data = self.recv(RECV_FULL_SIZE)
        if (len(data) > 0):
            self.tor_client.enqueue_send(data)
        else:
            logger.debug("received zero-length packet from fwder- teardown...")
            self.teardown()

    def handle_connect(self):
        logger.debug("forwarder connected!")
        
    def handle_close(self):
        self.teardown()
        
    def teardown(self):
        self.close()
        self.tor_client.close()
        
                
class TorClientHandler(AsyncoreTcp):
    def __init__(self, socket):
        AsyncoreTcp.__init__(self, socket)
        self.fwder = ForwarderHandler(self)

    def handle_read(self):
        data = self.recv(RECV_FULL_SIZE)
        if (len(data) > 0):
            self.fwder.enqueue_send(data)
        else:
            logger.debug("received zero-length packet from tor - teardown...")
            self.teardown()
            
    def handle_close(self):
        self.teardown()
        
    def teardown(self):
        self.close()
        self.fwder.close()

class TunnelForwarder(asyncore.dispatcher):
    def __init__(self):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        self.bind((DEFAULT_LOCAL_HOST, DEFAULT_LOCAL_PORT))
        self.listen(1)
        
    def handle_accept(self):
        logger.info("Received Connection from tor client - setting up tunnel...")
        socket, address = self.accept()
        TorClientHandler(socket)
        
if __name__ == "__main__":
    logging.basicConfig()
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.info("Starting Forwarder Proxy...")
    fwd_server = TunnelForwarder()
    
    try:
        asyncore.loop()
    except KeyboardInterrupt:
        logger.info("Tearing down...")
        fwd_server.close()
            