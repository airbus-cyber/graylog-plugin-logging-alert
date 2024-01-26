import json
import socket

_INPUT_ADDRESS = ('127.0.0.1', 12201)


class GelfInput:

    def __init__(self, api, identifier):
        self._api = api
        self._identifier = identifier
        self._socket = None

    def is_running(self):
        return self._api.gelf_input_is_running(self._identifier)

    def connect(self):
        self._socket = socket.create_connection(_INPUT_ADDRESS)

    def close(self):
        self._socket.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.close()

    def send(self, args):
        data = dict({'version': '1.1', 'host': 'host', 'short_message': 'short_message'}, **args)
        print('Sending {}'.format(data))
        message = '{}\0'.format(json.dumps(data))
        self._socket.send(message.encode())
