import io
import socket
import time

BUFFER_SIZE = 4096
LISTENING_ADDRESS = '0.0.0.0'

class Server():
    def __init__(self, protocol, src=LISTENING_ADDRESS, buff_size=BUFFER_SIZE):
        self.protocol = protocol
        self.src = src
        self.buff_size = buff_size

        if self.protocol.transport == 'UDP':
            self.socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
            self.socket.bind((self.src, self.protocol.dport))
        elif self.protocol.transport == 'TCP':
            self.socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
            self.socket.bind((self.src, self.protocol.dport))
            self.socket.listen(1)   # Support only one client
        else:
            raise ValueError('Transport layer not suppported')

    def recv(self):
        if self.protocol.transport == 'UDP':
            return self._recvfrom()
        elif self.protocol.transport == 'TCP':
            return self._recv()

    def _recv(self):
        ret = io.BytesIO()

        (client_socket, _) = self.socket.accept()

        try:
            data = client_socket.recv(self.buff_size)
            packet_size = self.protocol.packet.PACKET_SIZE
            while True:
                new_data = data
                while len(data) <= packet_size and len(new_data) != 0:
                    new_data = client_socket.recv(self.buff_size)
                    data += new_data
                (_, payload) = self.protocol.decode(data[:packet_size])
                ret.write(payload)
                data = data[packet_size:]
        except ValueError:
            pass
        except socket.timeout:
            print('chiton: WARNING: socket timeout')

        client_socket.close()

        return ret.getvalue()

    def _recvfrom(self):
        ret = io.BytesIO()

        (data, _) = self.socket.recvfrom(self.buff_size)
        (last_sequence, payload) = self.protocol.decode(data)

        try:
            self.socket.settimeout(2)
            while True:
                ret.write(payload)
                (data, _) = self.socket.recvfrom(self.buff_size)
                (new_sequence, payload) = self.protocol.decode(data)
                if ((new_sequence - last_sequence) != 1) and (new_sequence != 1) and (last_sequence != 0xffff):
                    print('chiton: WARNING: Missing or disordered packets: Sequence {} followed by {}'.format(last_sequence, new_sequence))
                last_sequence = new_sequence
        except ValueError:
            pass
        except socket.timeout:
            print('chiton: WARNING: socket timeout')

        self.socket.settimeout(None)

        return ret.getvalue()
