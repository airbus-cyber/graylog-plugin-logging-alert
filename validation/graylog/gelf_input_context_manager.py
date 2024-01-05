import socket
from graylog.gelf_input import GelfInput

_INPUT_ADDRESS = ('127.0.0.1', 12201)


class GelfInputContextManager:

    def __init__(self, api, identifier):
        self._api = api
        self._identifier = identifier
        self._socket = None

    def is_running(self):
        return self._api.gelf_input_is_running(self._identifier)
    
    def __enter__(self):
        self._socket = socket.create_connection(_INPUT_ADDRESS)
        return GelfInput(self._socket)

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self._socket.close()
