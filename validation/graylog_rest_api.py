import requests
from urllib import parse

STREAM_ALL_MESSAGES = "000000000000000000000001"
_AUTH = ('admin', 'admin')
_HEADERS = {'X-Requested-By': 'test-program'}


class GraylogRestApi:

    def __init__(self):
        self._session = requests.Session()
        self._session.auth = _AUTH
        self._session.headers.update(_HEADERS)

    def _build_url(self, path):
        return parse.urljoin('http://127.0.0.1:9000/api/', path)

    def get(self, path):
        url = self._build_url(path)
        response = self._session.get(url)
        print('GET {} => {}'.format(url, response.status_code))
        return response

    def put(self, path, payload):
        url = self._build_url(path)
        response = self._session.put(url, json=payload)
        print('PUT {} {} => {}'.format(url, payload, response.status_code))
        return response

    def post(self, path, payload=None):
        url = self._build_url(path)
        response = self._session.post(url, json=payload)
        print('POST {} {} => {}'.format(url, payload, response.status_code))
        return response
