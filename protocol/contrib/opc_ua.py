'''
ISO/IEC 19464:2014 - Advanced Message Queuing Protocol (AMQP) 1.0 layer for Scapy
'''

import struct

from scapy.error import Scapy_Exception
from scapy.layers.inet import TCP
from scapy.fields import Field, IntField, ByteField, ByteEnumField, ShortField
from scapy.packet import Packet, bind_layers


AMQP_TYPES = {
    0: 'AMQP',
    1: 'SASL'
}


PERFORMATIVES = {
    0x0000000000000010: 'Open',
    0x0000000000000011: 'Begin',
    0x0000000000000012: 'Attach',
    0x0000000000000013: 'Flow',
    0x0000000000000014: 'Transfer',
    0x0000000000000015: 'Disposition',
    0x0000000000000016: 'Detach',
    0x0000000000000017: 'End',
    0x0000000000000018: 'Close'
}


class AMQPNullField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, fmt='b')

    def i2m(self, pkt, x):
        return 0x40

    def m2i(self, pkt, x):
        return None

    def i2h(self, pkt, x):
        return 'null'


class AMQPBooleanField(Field):
    # True 0x41 or 0x56 0x01
    # False 0x42 or 0x56 0x00
    def __init__(self, name, default):
        Field.__init__(self, name, default)

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        value, size = self.m2i(pkt, s)
        return s[size:], value

    def i2m(self, pkt, x):
        ret = b''

        if x:
            ret = b'\x41'
        else:
            ret = b'\x42'

        return ret

    def m2i(self, pkt, x):
        if x[0] == 0x41:
            return True, 1
        elif (x[0] == 0x56) and (x[1] == 0x01):
            return True, 2
        elif x[0] == 0x42:
            return False, 1
        elif (x[0] == 0x56) and (x[1] == 0x00):
            return False, 2


class AMQPByteField(Field):
    # 0x50 with a following 1 byte value
    def __init__(self, name, default):
        Field.__init__(self, name, default)

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        value, size = self.m2i(pkt, s)
        return s[size:], value

    def i2m(self, pkt, x):
        return b'\x50' + struct.pack('>B', x)

    def m2i(self, pkt, x):
        if x[0] == 0x50:
            return x[1], 2


class AMQPShortField(Field):
    # TODO
    # 0x60 with a following 2 bytes value
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<2h")

    def i2m(self, pkt, x):
        if x is None:
            return b''


class AMQPIntField(Field):
    # 0x70 with a following 4 bytes value
    # 0x52 with a following 1 byte value ranging from 0 to 255 (inclusive)
    # 0x43 for 0 uint value
    def __init__(self, name, default):
        Field.__init__(self, name, default)

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        value, size = self.m2i(pkt, s)

        return s[size:], value

    def i2m(self, pkt, x):
        ret = b''

        if x == 0:
            ret = b'\x43'
        elif (x > 0) and (x <= 255):
            ret = b'\x52' + struct.pack('>B', x)
        elif (x > 255) and (x <= 0xffffffff):
            ret = b'\x70' + struct.pack('>I', x)

        return ret

    def m2i(self, pkt, x):
        mark = x[0]

        if mark == 0x43:
            return 0, 1
        elif mark == 0x52:
            return struct.unpack('>B', x[1])[0], 2
        elif mark == 0x70:
            return struct.unpack('>I', x[1:5])[0], 5


def int_to_long(value):
    ret = b''

    if value <= 0xff:
        ret = b'\x53' + struct.pack('>B', value)
    elif (value > 0xff) and (value <= 0xffffffff):
        ret = b'\x80' + struct.pack('>Q', value)

    return ret


def long_to_int(value):
    mark = value[0]

    if mark == 0:
        ret = 0
    elif mark == 0x53:
        ret = value[1]
    elif mark == 0x80:
        ret = struct.unpack('>Q', value[1:])[0]

    return ret


class AMQPLongField(Field):
    # 0x80 with a following 8 bytes value
    # 0x53 with a following 1 byte value ranging from 0 to 255 (inclusive)
    # 0x44 for 0 ulong value
    def __init__(self, name, default):
        Field.__init__(self, name, default)

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def i2m(self, pkt, x):
        return int_to_long(x)

    def m2i(self, pkt, x):
        raise NotImplementedError


class AMQPSignedByteField(Field):
    # TODO
    # 0x51 with a following 1 bytes value
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<2h")

    def i2m(self, pkt, x):
        if x is None:
            return b''


class AMQPSignedShortField(Field):
    # TODO
    # 0x61 with a following 2 bytes value
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<2h")

    def i2m(self, pkt, x):
        if x is None:
            return b''


class AMQPSignedIntField(Field):
    # TODO
    # 0x71 with a following 4 bytes value
    # 0x54 with a following 1 byte value ranging from 0 to 255 (inclusive)
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<2h")

    def i2m(self, pkt, x):
        if x is None:
            return b''


class AMQPSignedLongField(Field):
    # TODO
    # 0x81 with a following 8 bytes value
    # 0x55 with a following 1 byte value ranging from 0 to 255 (inclusive)
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<2h")

    def i2m(self, pkt, x):
        if x is None:
            return b''


class AMQPFloatField(Field):
    # TODO
    # 0x72 with a following 4 bytes IEEE 754-2008 binary32 value
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<2h")

    def i2m(self, pkt, x):
        if x is None:
            return b''


class AMQPDoubleField(Field):
    # TODO
    # 0x82 with a following 8 bytes IEEE 754-2008 binary64 value
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<2h")

    def i2m(self, pkt, x):
        if x is None:
            return b''


class AMQPDecimal32Field(Field):
    # TODO
    # 0x74 with a following 4 bytes IEEE 754-2008 decimal32 value
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<2h")

    def i2m(self, pkt, x):
        if x is None:
            return b''


class AMQPDecimal64Field(Field):
    # TODO
    # 0x84 with a following 8 bytes IEEE 754-2008 decimal64 value
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<2h")

    def i2m(self, pkt, x):
        if x is None:
            return b''


class AMQPDecimal128Field(Field):
    # TODO
    # 0x94 with a following 16 bytes IEEE 754-2008 decimal128 value
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<2h")

    def i2m(self, pkt, x):
        if x is None:
            return b''


class AMQPCharField(Field):
    # TODO
    # 0x73 with a following 4 bytes UTF-32BE value
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<2h")

    def i2m(self, pkt, x):
        if x is None:
            return b''


class AMQPTimestampField(Field):
    # TODO
    # 0x83 with a following 8 bytes Unix time_t [IEEE1003] encoding of UTC
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<2h")

    def i2m(self, pkt, x):
        if x is None:
            return b''


class AMQPUuidField(Field):
    # TODO
    # 0x98 with a following 16 bytes as defined by RFC-4122 section 4.1.2
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<2h")

    def i2m(self, pkt, x):
        if x is None:
            return b''


class AMQPBinaryField(Field):
    # 0xa0 following 1 byte size and 2^8 - 1 remaining binary data
    # 0xb0 following 4 byte size and 2^32 - 1 remaining binary data
    def __init__(self, name, default):
        Field.__init__(self, name, default)

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        value, size = self.m2i(pkt, s)
        return s[size:], value

    def i2m(self, pkt, x):
        ret = b''

        length = len(x)

        if length <= 0xff:
            ret = b'\xa0' + struct.pack('>B', length) + x
        elif (length > 0xff) and (length <= 0xffffffff):
            ret = b'\xb0' + struct.pack('>I', length) + x

        return ret

    def m2i(self, pkt, x):
        mark = x[0]

        if mark == 0xa0:
            lenght = x[1]
            return x[2:2+lenght], 2+lenght
        elif mark == 0xb0:
            lenght = struct.unpack('>I', x[1:5])[0]
            return x[5:5+lenght], 5+lenght


class AMQPStringField(Field):
    # TODO
    # 0xa1 following 1 byte size and 2^8 - 1 remaining UTF-8 Unicode string
    # 0xb1 following 4 byte size and 2^32 - 1 remaining UTF-8 Unicode string
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<2h")

    def i2m(self, pkt, x):
        if x is None:
            return b''


class AMQPSymbolField(Field):
    # TODO
    # 0xa3 following 1 byte size and 2^8 - 1 remaining ASCII characters
    # 0xb3 following 4 byte size and 2^32 - 1 remaining ASCII characters
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<2h")

    def i2m(self, pkt, x):
        if x is None:
            return b''


class AMQPListField(Field):
    # TODO
    # 0x45 empty list
    # 0xc0 following 1 byte size and up to 2^8 - 1 list elements with total size less than 2^8 octets
    # 0xd0 following 4 byte size and up to 2^32 - 1 list elements with total size less than 2^32 octets
    def __init__(self, name, default):
        Field.__init__(self, name, default)

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def i2m(self, pkt, x):
        ret = b''

        length = len(x)

        if length == 0:
            return b'\x45'
        elif length > 0 and length <= 0xff:
            ret = b'\xc0'
        elif length > 0xff and length <= 0xffffffff:
            ret = b'\xd0'

        for field in x:
            import pdbº
            pdb.set_trace()

        return ret

    def i2h(self, pkt, x):
        ret = []

        for field in x:
            ret.append({field.name: field.i2h(field, field.default)})

        return ret

    def m2i(self, pkt, x):
        raise NotImplementedError


class AMQPMapField(Field):
    # TODO: Key/value data structure, like a dict in Python
    # 0xc1 following 1 byte size and up to 2^8 - 1  octets of encoded map data
    # 0xd1 following 4 byte size and up to 2^32 - 1 octets of encoded map data
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<2h")

    def i2m(self, pkt, x):
        if x is None:
            return b''


class AMQPArrayField(Field):
    # TODO: sequence of values of a single type
    # 0xe0 following 1 byte size and up to 2^8 - 1 array elements with total size less than 2^8 octets
    # 0xf0 following 4 byte size and up to 2^32 - 1 array elements with total size less than 2^32 octets
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<2h")

    def i2m(self, pkt, x):
        if x is None:
            return b''


class AMQPCodeField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default)

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def getfield(self, pkt, s):
        # FIXME: do not consume the list sequence that is following the code field
        value = self.m2i(pkt, s)

        if value <= 0xff:
            s = s[6:]
        elif (value > 0xff) and (value <= 0xffffffff):
            s = s[13:]

        return s, value

    def i2m(self, pkt, x):
        return b'\x00' + int_to_long(x)

    def i2h(self, pkt, x):
        return PERFORMATIVES[x]

    def m2i(self, pkt, x):
        x = x[1:]
        return long_to_int(x)


class AMQPOpen(Packet):
    name = "AMQP Open performative"

    fields_desc = [
        AMQPCodeField('code', 0x0000000000000010)
    ]


class AMQPBegin(Packet):
    name = "AMQP Begin performative"

    fields_desc = [
        AMQPCodeField('code', 0x0000000000000011)
    ]


class AMQPAttach(Packet):
    name = "AMQP Attach performative"

    fields_desc = [
        AMQPCodeField('code', 0x0000000000000012)
    ]


class AMQPFlow(Packet):
    name = "AMQP Flow performative"

    fields_desc = [
        AMQPCodeField('code', 0x0000000000000013)
    ]


class AMQPTransfer(Packet):
    name = "AMQP Transfer performative"

    fields_desc = [
        AMQPIntField('handle', 0),
        AMQPIntField('delivery_id', 0),
        AMQPBinaryField('delivery_tag', b'\x00\x00\x00\x00'),
        AMQPIntField('message_format', 0),
        AMQPBooleanField('settled', False),
        AMQPBooleanField('more', False),
        AMQPByteField('rcv_settle_mode', 0),
        AMQPBinaryField('state', b''),
        AMQPBooleanField('resume', False),
        AMQPBooleanField('aborted', False),
        AMQPBooleanField('batchable', False)
    ]

    def post_build(self, p, pay):
        ''' Insert Transfer prefix and constructor a list of AMQP arguments from 'handle' towards '''
        return b'\x00\x53\x14' + b'\xc0' + struct.pack('>B', len(p)) + struct.pack('>B', len(self.fields_desc)) + p + pay

    def pre_dissect(self, s):
        ''' Remove Transfer prefix and AMQP list'''
        if s[:3] == b'\x00\x53\x14':
            return s[6:]

    def guess_payload_class(self, payload):
        code = payload[:3]

        if code == b'\x00\x53\x75':
            return AMQPData
        else:
            return Packet.guess_payload_class(self, payload)


class AMQPDisposition(Packet):
    name = "AMQP Disposition performative"

    fields_desc = [
        AMQPCodeField('code', 0x0000000000000015)
    ]


class AMQPDetach(Packet):
    name = "AMQP Detach performative"

    fields_desc = [
        AMQPCodeField('code', 0x0000000000000016)
    ]


class AMQPEnd(Packet):
    name = "AMQP End performative"

    fields_desc = [
        AMQPCodeField('code', 0x0000000000000017)
    ]


class AMQPClose(Packet):
    name = "AMQP Close performative"

    fields_desc = [
        AMQPCodeField('code', 0x0000000000000018)
    ]


class AMQP(Packet):
    name = "AMQP 1.0"

    fields_desc = [
        IntField('size', 0),
        ByteField('doff', 2),
        ByteEnumField('type', 0, AMQP_TYPES),
        ShortField('channel', 0)
    ]

    def post_build(self, p, pay):
        ''' Recalculate total packet size '''
        # TODO: calculate doff instead of fixed 2
        total_len = len(p + pay)
        p = struct.pack(">I", total_len) + p[4:]
        return p + pay

    def guess_payload_class(self, payload):
        code = payload[:3]

        if code == b'\x00\x53\x14':
            return AMQPTransfer
        else:
            return Packet.guess_payload_class(self, payload)


class AMQPData(Packet):
    name = "AMQP Opaque binary data"

    fields_desc = [
        AMQPBinaryField('data', b'')
    ]

    def post_build(self, p, pay):
        ''' Insert AMQP Data constructor before actual data '''
        return b'\x00\x53\x75' + p + pay

    def pre_dissect(self, s):
        ''' Remove AMQP Data constructor before actual data '''
        if s[:3] == b'\x00\x53\x75':
            return s[3:]


bind_layers(TCP, AMQP, sport=5672)
bind_layers(TCP, AMQP, dport=5672)
