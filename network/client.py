import time
import socket

import chiton.layers.inet as inet

class Client():
    def __init__(self, protocol, dst):
        self.protocol = protocol
        self.dst = dst

        if self.protocol.transport == inet.TransportLayer.UDP:
            self.socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        elif self.protocol.transport == inet.TransportLayer.TCP:
            self.socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
            self.socket.connect((self.dst, self.protocol.dport))
        else:
            raise ValueError('Transport layer not suppported')

    def send(self, buffer, delay=0):
        if self.protocol.transport == inet.TransportLayer.UDP:
            self._sendto(buffer, delay=delay)
        elif self.protocol.transport == inet.TransportLayer.TCP:
            self._send(buffer, delay=delay)
    
    def _send(self, buffer, delay):
        for packet in self.protocol.encode(buffer):
            if delay: time.sleep(delay)
            self.socket.sendall(packet)

        self.socket.close()

    def _sendto(self, buffer, delay):
        for packet in self.protocol.encode(buffer):
            if delay: time.sleep(delay)
            self.socket.sendto(packet, (self.dst, self.protocol.dport))
