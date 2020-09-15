class Packet():
    def chunk(self, data, size):
        return [data[i:size+i] for i in range(0, len(data), size)]

    def craft(self, data, message_id=''):
        raise NotImplementedError('craft function not implemented')

    def dissect(self, data, message_id=''):
        raise NotImplementedError('dissect function not implemented')
