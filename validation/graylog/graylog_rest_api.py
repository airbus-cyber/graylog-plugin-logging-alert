from urllib import parse
import requests
from requests.exceptions import ConnectionError
from graylog.gelf_input import GelfInput

STREAM_ALL_MESSAGES = "000000000000000000000001"
_AUTH = ('admin', 'admin')
_HEADERS = {'X-Requested-By': 'test-program'}

_DEFAULT_LOG_BODY = 'type: alert\nid: ${logging_alert.id}\nseverity: ${logging_alert.severity}\napp: graylog\nsubject: ${event_definition_title}\nbody: ${event_definition_description}\n${if backlog && backlog[0]} src: ${backlog[0].fields.src_ip}\nsrc_category: ${backlog[0].fields.src_category}\ndest: ${backlog[0].fields.dest_ip}\ndest_category: ${backlog[0].fields.dest_category}\n${end}'


class GraylogRestApi:

    def _build_url(self, path):
        return parse.urljoin('http://127.0.0.1:9000/api/', path)

    def _get(self, path):
        url = self._build_url(path)
        response = requests.get(url, auth=_AUTH, headers=_HEADERS)
        print('GET {} => {}'.format(url, response.status_code))
        return response

    def _put(self, path, payload):
        url = self._build_url(path)
        response = requests.put(url, json=payload, auth=_AUTH, headers=_HEADERS)
        print('PUT {} {} => {}'.format(url, payload, response.status_code))
        return response

    def _post(self, path, payload=None):
        url = self._build_url(path)
        response = requests.post(url, json=payload, auth=_AUTH, headers=_HEADERS)
        print('POST {} {} => {}'.format(url, payload, response.status_code))
        return response

    def default_deflector_is_up(self):
        try:
            response = self._get('system/deflector')
            body = response.json()
            if body['is_up']:
                return True
            return False
        except ConnectionError:
            return False

    def create_notification(self, split_fields=None, single_message=False, log_body=_DEFAULT_LOG_BODY, description=''):
        if split_fields is None:
            split_fields = []
        notification_configuration = {
        'config': {
                'log_body': log_body,
                'single_notification': single_message,
                'split_fields': split_fields,
                'aggregation_time': 10,
                'type': 'logging-alert-notification'
            },
            'description': description,
            'title': 'N'
        }
        response = self._post('events/notifications', notification_configuration)
        notification = response.json()
        return notification['id']

    def create_event_definition(self, notification_identifier, streams=None, backlog_size=None, conditions=None,
                                series=None, period=5):
        if series is None:
            series = []
        if conditions is None:
            conditions = {}
        if streams is None:
            streams = []
        events_definition_configuration = {
            'alert': True,
            'config': {
                'conditions': conditions,
                'execute_every_ms': period*1000,
                'group_by': [],
                'query': '',
                'query_parameters': [],
                'search_within_ms': period*1000,
                'series': series,
                'streams': streams,
                'type': 'aggregation-v1'
            },
            'description': '',
            'field_spec': {},
            'key_spec': [],
            'notification_settings': {
                'backlog_size': backlog_size,
                'grace_period_ms': 0
            },
            'notifications': [{
                'notification_id': notification_identifier
            }],
            'priority': 2,
            'title': 'E'
        }
        self._post('events/definitions', events_definition_configuration)

    def gelf_input_is_running(self, identifier):
        response = self._get('system/inputstates/')
        body = response.json()
        for state in body['states']:
            if state['id'] != identifier:
                continue
            return state['state'] == 'RUNNING'
        return False

    def create_gelf_input(self):
        payload = {
            'configuration': {
                'bind_address': '0.0.0.0',
                'decompress_size_limit': 8388608,
                'max_message_size': 2097152,
                'number_worker_threads': 8,
                'override_source': None,
                'port': 12201,
                'recv_buffer_size': 1048576,
                'tcp_keepalive': False,
                'tls_cert_file': '',
                'tls_client_auth': 'disabled',
                'tls_client_auth_cert_file': '',
                'tls_enable': False,
                'tls_key_file': 'admin',
                'tls_key_password': 'admin',
                'use_null_delimiter': True
            },
            'global': True,
            'title': 'Inputs',
            'type': 'org.graylog2.inputs.gelf.tcp.GELFTCPInput'
        }
        response = self._post('system/inputs', payload)
        identifier = response.json()['id']
        return GelfInput(self, identifier)

    def create_stream_with_rule(self, title, field, value):
        response = self._get('system/indices/index_sets')
        default_index_set_identifier = response.json()['index_sets'][0]['id']
        stream = {
            'description': title,
            'index_set_id': default_index_set_identifier,
            'remove_matches_from_default_stream': False,
            'title': title
        }
        response = self._post('streams', stream)
        stream_identifier = response.json()['stream_id']
        rule = {
            'description': '',
            'field': field,
            'inverted': False,
            'type': 1,
            'value': value
        }
        self._post('streams/{}/rules'.format(stream_identifier), rule)
        self._post('streams/{}/resume'.format(stream_identifier))
        return stream_identifier

    def update_plugin_configuration(self, aggregation_stream):
        plugin_configuration = {
            'aggregation_stream': aggregation_stream,
            'aggregation_time': '10',
            'alert_tag': 'LoggingAlert',
            'field_alert_id': 'id',
            'log_body': _DEFAULT_LOG_BODY,
            'separator': ' | ',
            'severity': 'LOW',
            'overflow_tag': 'LoggingOverflow'
        }
        self._put('system/cluster_config/com.airbus_cyber_security.graylog.events.config.LoggingAlertConfig', plugin_configuration)

    def configure_telemetry(self):
        configuration = {
            'telemetry_enabled': False,
            'telemetry_permission_asked': True
        }
        self._put('telemetry/user/settings', configuration)

