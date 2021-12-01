# to create and populate the test venv:
# * python3 -m venv venv
# * source venv/bin/activate
# * pip install -r requirements.txt 
# to execute these tests:
# * activate venv
#   source ./venv/bin/activate
# * execute tests
#   python -m unittest

from unittest import TestCase
import time
from graylog_server import GraylogServer
from graylog_rest_api import GraylogRestApi

_PERIOD = 1


class Test(TestCase):

    def setUp(self) -> None:
        # TODO maybe merge _graylog and _graylog_rest_api
        self._graylog = GraylogServer('../runtime')
        self._graylog.start()
        self._graylog_rest_api = GraylogRestApi()
        self._graylog_rest_api.wait_until_graylog_has_started()

    def tearDown(self) -> None:
        self._graylog.stop()

    def _parse_notification_log(self, logs):
        for log in logs.splitlines():
            if 'INFO : LoggingAlert' not in log:
                continue
            log_sections = log.split(' | ')
            _, identifier = log_sections[2].split(': ')
            return identifier
        raise AssertionError('Notification log not found in logs: \'{}\''.format(logs))

    def test_process_an_event_should_not_fail_for_a_notification_with_aggregation_issue30(self):
        notification_identifier = self._graylog_rest_api.create_notification()
        self._graylog_rest_api.create_event_definition(notification_identifier, period=_PERIOD)

        with self._graylog_rest_api.create_gelf_input() as gelf_inputs:
            gelf_inputs.send({})
            time.sleep(2*_PERIOD)

            gelf_inputs.send({})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop'})
            time.sleep(_PERIOD)
            logs = self._graylog.extract_latest_logs()
            self.assertNotIn('ElasticsearchException', logs)

    def test_notification_identifier_should_not_be_from_the_message_in_the_baclog_issue22(self):
        notification_identifier = self._graylog_rest_api.create_notification()
        self._graylog_rest_api.create_event_definition(notification_identifier, backlog_size=50, period=_PERIOD)

        with self._graylog_rest_api.create_gelf_input() as gelf_inputs:
            gelf_inputs.send({'_id': 'message_identifier'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop'})
            # wait long enough for processing to terminate (even on slow machines)
            time.sleep(10)
            logs = self._graylog.extract_latest_logs(5)
            notification_identifier = self._parse_notification_log(logs)
            self.assertNotEqual(notification_identifier, 'message_identifier')

