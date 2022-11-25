from enum import Enum

import chiton.protocol as protocol
import chiton.layers.inet as inet
import chiton.contrib.amqp as amqp

""" Default AMQP port """
PORT = 5672

""" Packet types """
class AMQPPerformatives(Enum):
    OPEN = 1
    BEGIN = 2
    ATTACH = 3
    FLOW = 4
    TRANSFER = 5
    DISPOSITION = 6
    DETACH = 7
    END = 8
    CLOSE = 9

class AMQP(protocol.Protocol):
    def __init__(self, packet=AMQPPerformatives.TRANSFER, dport=PORT):
        super().__init__()
        self.transport = inet.TransportLayer.TCP
        self.packet = self._get_packet_type(packet)
        self.dport = dport

    def _get_packet_type(self, packet):
        if packet == AMQPPerformatives.TRANSFER:
            return AMQPTransfer()
    
        raise ValueError('AMQP performative not supported')

    def encode(self, data):
        for chunk in self.packet.chunk(data, self.packet.payload_length):
            yield self.packet.craft(chunk)

    def decode(self, data):
        return self.packet.dissect(data)


class AMQPTransfer(protocol.Packet):
    USEFUL_PAYLOAD = 65440
    PACKET_SIZE = 40 + USEFUL_PAYLOAD

    def __init__(self, payload_length=USEFUL_PAYLOAD):
        self.payload_length = payload_length

    def craft(self, data, final=False):
        p = amqp.AMQP()/amqp.AMQPTransfer()/amqp.AMQPData(data=data)

        p.delivery_id = 0xffffffff if final else 0x00000000

        return bytes(p)

    def dissect(self, data):
        if len(data) == 0:
            raise ValueError('Attempting to dissect an empty stream')

        payload = b''

        p = amqp.AMQP(data)
        final = p.delivery_id

        if final == 0xffffffff:
            raise ValueError('Attempting to dissect end of stream packet')

        payload = p.data

        return (0, payload)
