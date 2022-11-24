from enum import Enum

import scapy.packet as base
import scapy.contrib.coap as coap

import chiton.protocol as protocol
import chiton.layers.inet as inet

""" Default CoAP port """
PORT = 5683

""" Packet types """
class CoAPMethods(Enum):
    GET = 1
    POST = 2
    PUT = 3
    DELETE = 4

class CoAP(protocol.Protocol):
    def __init__(self, pkt=CoAPMethods.POST, dport=PORT):
        super().__init__()
        self.transport = inet.UDP
        self.pkt = self._get_packet_type(pkt)
        self.dport = dport

    def _get_packet_type(self, packet):
        if packet == CoAPMethods.GET:
            return URI(code=CoAPMethods.GET.value)
        elif packet == CoAPMethods.POST:
            return Payload(code=CoAPMethods.POST.value)
        elif packet == CoAPMethods.PUT:
            return Payload(code=CoAPMethods.PUT.value)
        elif packet == CoAPMethods.DELETE:
            return URI(code=CoAPMethods.DELETE.value)

        raise ValueError('CoAP method not supported')

    def encode(self, data):
        for chunk in self.pkt.chunk(data, self.pkt.payload_length):
            message_id = next(self.counter)
            yield self.pkt.craft(chunk, message_id)
        
        """ Send end message """
        yield self.pkt.craft(b'', message_id=protocol.EOF)

    def decode(self, data):
        return self.pkt.dissect(data)

class URI(protocol.Packet):
    USEFUL_PAYLOAD = 250

    def __init__(self, code, payload_length=USEFUL_PAYLOAD):
        self.code = code
        self.payload_length = payload_length

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

        if sequence == protocol.EOF:
            raise ValueError('Attempting to dissect end of stream packet')

        payload = packet.token

        for option in packet.options:
            payload += option[1]

        return (sequence, payload)

class Payload(protocol.Packet):
    USEFUL_PAYLOAD = 1245

    def __init__(self, code, payload_length=USEFUL_PAYLOAD):
        self.code = code
        self.payload_length = payload_length

    def craft(self, data, message_id):
        pkt = coap.CoAP(code=self.code, msg_id=message_id, token=data[:0x08], paymark=b'\xff')      # paymark to indicate beginning of the payload

        options = [('Uri-Path', data[0x08:0x08+0xff])]
        """ application/octet-stream """
        options.append(('Content-Format', b'\x2a'))
        pkt.options = options

        pkt /= base.Raw(data[0x08+0xff:])

        return bytes(pkt)

    def dissect(self, data):
        pkt = coap.CoAP(data)
        sequence = pkt.msg_id

        if sequence == protocol.EOF:
            raise ValueError('Attempting to dissect end of stream packet')

        payload = pkt.token

        for (key, value) in pkt.options:
            if key == 'Uri-Path':
                payload += value

        payload += pkt.payload.load

        return (sequence, payload)
