from enum import Enum

import scapy.contrib.mqtt as mqtt
import chiton.protocol as protocol
import chiton.layers.inet as inet

""" Default MQTT port """
PORT = 1883

""" Packet types """
class MQTTControlPackets(Enum):
    CONNECT = 1
    CONNACK = 2
    PUBLISH = 3
    PUBACK = 4
    PUBREC = 5
    PUBREL = 6
    PUBCOMP = 7
    SUBSCRIBE = 8
    SUBACK = 9
    UNSUBSCRIBE = 10
    UNSUBACK = 11
    PINGREQ = 12
    PINGRESP = 13
    DISCONNECT = 14
    AUTH = 15

class MQTT(protocol.Protocol):
    def __init__(self, pkt=MQTTControlPackets.PUBLISH, dport=PORT):
        super().__init__()
        self.transport = inet.TransportLayer.TCP
        self.pkt = self._get_packet_type(pkt)
        self.dport = dport

    def _get_packet_type(self, packet):
        if packet == MQTTControlPackets.CONNECT:
            return MQTTConnect()
        elif packet == MQTTControlPackets.PUBLISH:
            return MQTTPublish()

        raise ValueError('MQTT control packet not supported')

    def encode(self, data):
        for chunk in self.pkt.chunk(data, self.pkt.payload_length):
            yield self.pkt.craft(chunk)

    def decode(self, data):
        if len(data) > self.pkt.PACKET_SIZE:
            ret = b''
            print('chiton: WARNING: Several MQTT packets in a single TCP/IP packet, try to reduce client sent frequency')
            for chunk in self.pkt.chunk(data, self.pkt.PACKET_SIZE):
                ret += self.pkt.dissect(chunk)
            return ret
        else:
            return self.pkt.dissect(data)

class MQTTConnect(protocol.Packet):
    USEFUL_PAYLOAD = 23
    PACKET_SIZE = 14 + USEFUL_PAYLOAD

    def __init__(self, payload_length=USEFUL_PAYLOAD):
        self.payload_length = payload_length

    def craft(self, data, final=False):
        # ClientID: UTF-8 Encoded String but 23 bytes maximum
        # (<https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901058>)
        # with alphabet '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
        p = mqtt.MQTT()/mqtt.MQTTConnect(clientIdlen=len(data), clientId=data, protolevel=4, protoname='MQTT')

        p.reserved = 1 if final else 0

        return bytes(p)

    def dissect(self, data):
        payload = b''

        p = mqtt.MQTT(data)
        final = p.reserved

        if final == 1:
            raise ValueError('Attempting to dissect end of stream packet')

        payload = p.clientId

        return (0, payload)

class MQTTPublish(protocol.Packet):
    USEFUL_PAYLOAD = 65499
    PACKET_SIZE = 8 + USEFUL_PAYLOAD

    def __init__(self, payload_length=USEFUL_PAYLOAD):
        self.payload_length = payload_length

    def craft(self, data, final=False):
        if final: 
            return bytes(mqtt.MQTT(QOS=1)/mqtt.MQTTPublish(msgid=1, topic=b'\x00', value='\x00'))
        else:
            return  bytes(mqtt.MQTT(QOS=1)/mqtt.MQTTPublish(msgid=0, topic=data[:255], value=data[255:]))

    def dissect(self, data):
        if len(data) == 0:
            raise ValueError('Attempting to dissect an empty stream')

        payload = b''

        p = mqtt.MQTT(data)
        final = p.msgid

        if final == 1:
            raise ValueError('Attempting to dissect end of stream packet')
        
        payload += p.topic
        payload += p.value

        return (0, payload)
