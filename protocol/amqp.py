import chiton.protocol.contrib.amqp as amqp
import chiton.protocol.packet as packet

# Packet types
OPEN = 1
BEGIN = 2
ATTACH = 3
FLOW = 4
TRANSFER = 5
DISPOSITION = 6
DETACH = 7
END = 8
CLOSE = 9

PORT = 5672


class AMQP:
    def __init__(self, packet=TRANSFER, dport=PORT):
        self.transport = 'TCP'
        self.packet = self.get_packet_type(packet)
        self.dport = dport

    def get_packet_type(self, packet):
        if packet == TRANSFER:
            return AMQPTransfer()
        else:
            raise ValueError('Not supported AMQP packet')

    def encode(self, data):
        for chunk in self.packet.chunk(data, self.packet.payload_lenght):
            yield self.packet.craft(chunk)

    def decode(self, data):
        return self.packet.dissect(data)


class AMQPTransfer(packet.Packet):
    USEFUL_PAYLOAD = 65440
    PACKET_SIZE = 40 + USEFUL_PAYLOAD

    def __init__(self, payload_lenght=USEFUL_PAYLOAD):
        self.payload_lenght = payload_lenght

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
