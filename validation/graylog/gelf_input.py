import json


class GelfInput:

    def __init__(self, input_socket):
        self._socket = input_socket

    def send(self, args):
        data = dict({'version': '1.1', 'host': 'host', 'short_message': 'short_message'}, **args)
        print('Sending {}'.format(data))
        message = '{}\0'.format(json.dumps(data))
        self._socket.send(message.encode())

