import itertools
import scapy.contrib.coap as coap
import scapy.packet as base
import chiton.protocol.packet as packet

# Packet types
GET = 0
POST = 1
PUT = 2
DELETE = 3

PORT = 5683
END_OF_STREAM = 0

class CoAP:
    def __init__(self, packet=GET, dport=PORT):
        self.transport = 'UDP'
        self.packet = self.get_packet_type(packet)
        self.counter = itertools.cycle(range(0x01, 0x10000))
        self.dport = dport

    def get_packet_type(self, packet):
        if packet == GET:
            return URI(code=1)
        elif packet == POST:
            return Payload(code=2)
        elif packet == PUT:
            return Payload(code=3)
        elif packet == DELETE:
            return URI(code=4)
        else:
            raise ValueError('Not supported CoAP packet')

    def encode(self, data):
        for chunk in self.packet.chunk(data, self.packet.payload_lenght):
            message_id = self.counter.__next__()
            yield self.packet.craft(chunk, message_id)

    def decode(self, data):
        return self.packet.dissect(data)

class URI(packet.Packet):
    USEFUL_PAYLOAD = 250

    def __init__(self, code, payload_lenght=USEFUL_PAYLOAD):
        self.code = code
        self.payload_lenght = payload_lenght

    def craft(self, data, message_id):
        packet = coap.CoAP(code=self.code, msg_id=message_id, token=data[:0x08])

        options = []
        for chunk in self.chunk(data[0x08:], size=63):
            options.append(('Uri-Path', chunk))

        packet.options = options

        return bytes(packet)

    def dissect(self, data):
        packet = coap.CoAP(data)
        sequence = packet.msg_id

        if sequence == END_OF_STREAM:
            raise ValueError('Attempting to dissect end of stream packet')

        payload = packet.token

        for option in packet.options:
            payload += option[1]

        return (sequence, payload)

class Payload(packet.Packet):
    USEFUL_PAYLOAD = 1245

    def __init__(self, code, payload_lenght=USEFUL_PAYLOAD):
        self.code = code
        self.payload_lenght = payload_lenght

    def craft(self, data, message_id):
        packet = coap.CoAP(code=self.code, msg_id=message_id, token=data[:0x08], paymark=b'\xff')

        options = [('Uri-Path', data[0x08:0x08+0xff])]
        # application/octet-stream
        options.append(('Content-Format', b'\x2a'))
        packet.options = options

        packet /= base.Raw(data[0x08+0xff:])

        return bytes(packet)

    def dissect(self, data):
        packet = coap.CoAP(data)
        sequence = packet.msg_id

        if sequence == END_OF_STREAM:
            raise ValueError('Attempting to dissect end of stream packet')

        payload = packet.token

        for (key, value) in packet.options:
            if key == 'Uri-Path':
                payload += value

        payload += packet.payload.load

        return (sequence, payload)
