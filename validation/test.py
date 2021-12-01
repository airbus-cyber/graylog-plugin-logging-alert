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

_PERIOD = 5


class Test(TestCase):

    def setUp(self) -> None:
        # TODO maybe merge _graylog and _graylog_rest_api
        self._graylog = GraylogServer('../runtime')
        self._graylog.start()
        self._graylog_rest_api = GraylogRestApi()
        self._graylog_rest_api.wait_until_graylog_has_started()

    def tearDown(self) -> None:
        self._graylog.stop()

    def test_process_an_event_should_not_fail_for_a_notification_with_aggregation(self):
        notification_identifier = self._graylog_rest_api.create_notification()
        self._graylog_rest_api.create_event_definition(notification_identifier, _PERIOD)
        with self._graylog_rest_api.create_gelf_input() as gelf_inputs:
            gelf_inputs.send({})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop'})
            time.sleep(2*_PERIOD)

            gelf_inputs.send({})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop'})
            logs = self._graylog.extract_logs(2*_PERIOD)
            self.assertNotIn('ElasticsearchException', logs)

