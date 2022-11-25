import itertools

""" Range of message IDs to detect messages disorder or dropped """
MSG_ID_START = 1
MSG_ID_END = 0x10000
""" Last packet code """
EOF = 0

class Protocol():
    def __init__(self):
        self.counter = itertools.cycle(range(MSG_ID_START, MSG_ID_END))

    def encode(self, data):
        raise NotImplementedError('encode function not implemented')

    def decode(self, data):
        raise NotImplementedError('decode function not implemented')

class Packet():
    """
    Any protocol packet MUST inherit from this class
    """
    def chunk(self, data, size):
        """ Split data in size blocks """
        return [data[i:size+i] for i in range(0, len(data), size)]

    def craft(self, data, message_id):
        raise NotImplementedError('craft function not implemented')

    def dissect(self, data, message_id):
        raise NotImplementedError('dissect function not implemented')
