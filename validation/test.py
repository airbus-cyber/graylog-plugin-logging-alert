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
            # wait long enough for potential exception to occur (even on slow machines)
            time.sleep(2*_PERIOD)
            logs = self._graylog.extract_latest_logs()
            self.assertNotIn('ElasticsearchException', logs)

    def test_notification_identifier_should_not_be_from_the_message_in_the_backlog_issue22(self):
        notification_definition_identifier = self._graylog_rest_api.create_notification()
        self._graylog_rest_api.create_event_definition(notification_definition_identifier, backlog_size=50, period=_PERIOD)

        with self._graylog_rest_api.create_gelf_input() as gelf_inputs:
            gelf_inputs.send({'_id': 'message_identifier'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop'})
            # wait long enough for processing to terminate (even on slow machines)
            time.sleep(2*_PERIOD)
            logs = self._graylog.extract_latest_logs(5)
            notification_identifier = self._parse_notification_log(logs)
            self.assertNotEqual(notification_identifier, 'message_identifier')

    def test_aggregation_should_reuse_the_notification_identifier(self):
        stream_input_identifier = self._graylog_rest_api.create_stream_with_rule('input', 'stream', 'input')
        stream_log_identifier = self._graylog_rest_api.create_stream_with_rule('log', 'stream', 'log')
        self._graylog_rest_api.create_stream_with_rule('pop', 'stream', 'pop')
        plugin_configuration = {
            'aggregation_stream': stream_log_identifier,
            'aggregation_time': '10',
            'alert_tag': 'LoggingAlert',
            'field_alert_id': 'id',
            'log_body': 'type: alert\nid: ${logging_alert.id}\nseverity: ${logging_alert.severity}\napp: graylog\nsubject: ${event_definition_title}\nbody: ${event_definition_description}\n${if backlog && backlog[0]} src: ${backlog[0].fields.src_ip}\nsrc_category: ${backlog[0].fields.src_category}\ndest: ${backlog[0].fields.dest_ip}\ndest_category: ${backlog[0].fields.dest_category}\n${end}',
            'overflow_tag': 'LoggingOverflow',
            'separator': ' | ',
            'severity': 'LOW'
        }
        self._graylog_rest_api.put('system/cluster_config/com.airbus_cyber_security.graylog.events.config.LoggingAlertConfig', plugin_configuration)
        notification_definition_identifier = self._graylog_rest_api.create_notification()
        self._graylog_rest_api.create_event_definition(notification_definition_identifier, streams=[stream_input_identifier], period=_PERIOD)

        with self._graylog_rest_api.create_gelf_input() as gelf_inputs:
            gelf_inputs.send({'_stream': 'input'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            time.sleep(2 * _PERIOD)

            logs = self._graylog.extract_latest_logs(5)
            notification_identifier1 = self._parse_notification_log(logs)

            gelf_inputs.send({'_id': notification_identifier1, '_stream': 'log'})
            gelf_inputs.send({'_stream': 'input'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            time.sleep(_PERIOD)

            logs = self._graylog.extract_latest_logs(5)
            notification_identifier2 = self._parse_notification_log(logs)

            self.assertEqual(notification_identifier2, notification_identifier1)

    def test_aggregation_should_not_reuse_identifier_from_different_event_definition(self):
        stream_input1_identifier = self._graylog_rest_api.create_stream_with_rule('input1', 'stream', 'input1')
        stream_input2_identifier = self._graylog_rest_api.create_stream_with_rule('input2', 'stream', 'input2')
        stream_log_identifier = self._graylog_rest_api.create_stream_with_rule('log', 'stream', 'log')
        self._graylog_rest_api.create_stream_with_rule('pop', 'stream', 'pop')
        plugin_configuration = {
            'aggregation_stream': stream_log_identifier,
            'aggregation_time': '10',
            'alert_tag': 'LoggingAlert',
            'field_alert_id': 'id',
            'log_body': 'type: alert\nid: ${logging_alert.id}\nseverity: ${logging_alert.severity}\napp: graylog\nsubject: ${event_definition_title}\nbody: ${event_definition_description}\n${if backlog && backlog[0]} src: ${backlog[0].fields.src_ip}\nsrc_category: ${backlog[0].fields.src_category}\ndest: ${backlog[0].fields.dest_ip}\ndest_category: ${backlog[0].fields.dest_category}\n${end}',
            'overflow_tag': 'LoggingOverflow',
            'separator': ' | ',
            'severity': 'LOW'
        }
        self._graylog_rest_api.put('system/cluster_config/com.airbus_cyber_security.graylog.events.config.LoggingAlertConfig', plugin_configuration)
        notification_definition_identifier = self._graylog_rest_api.create_notification()
        self._graylog_rest_api.create_event_definition(notification_definition_identifier,
                                                       streams=[stream_input1_identifier],
                                                       period=_PERIOD)
        self._graylog_rest_api.create_event_definition(notification_definition_identifier,
                                                       streams=[stream_input2_identifier],
                                                       period=_PERIOD)

        with self._graylog_rest_api.create_gelf_input() as gelf_inputs:
            gelf_inputs.send({'_stream': 'input1'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            time.sleep(2 * _PERIOD)

            logs = self._graylog.extract_latest_logs(5)
            notification_identifier1 = self._parse_notification_log(logs)
            gelf_inputs.send({'_id': notification_identifier1, '_stream': 'log'})
            gelf_inputs.send({'_stream': 'input2'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            time.sleep(_PERIOD)

            logs = self._graylog.extract_latest_logs(5)
            notification_identifier2 = self._parse_notification_log(logs)

            self.assertNotEqual(notification_identifier2, notification_identifier1)

    def test_aggregation_should_not_reuse_the_notification_identifier_when_there_is_a_split_field_with_a_different_value(self):
        stream_input_identifier = self._graylog_rest_api.create_stream_with_rule('input', 'stream', 'input')
        stream_log_identifier = self._graylog_rest_api.create_stream_with_rule('log', 'stream', 'log')
        self._graylog_rest_api.create_stream_with_rule('pop', 'stream', 'pop')
        plugin_configuration = {
            'aggregation_stream': stream_log_identifier,
            'aggregation_time': '10',
            'alert_tag': 'LoggingAlert',
            'field_alert_id': 'id',
            'log_body': 'type: alert\nid: ${logging_alert.id}\nseverity: ${logging_alert.severity}\napp: graylog\nsubject: ${event_definition_title}\nbody: ${event_definition_description}\n${if backlog && backlog[0]} src: ${backlog[0].fields.src_ip}\nsrc_category: ${backlog[0].fields.src_category}\ndest: ${backlog[0].fields.dest_ip}\ndest_category: ${backlog[0].fields.dest_category}\n${end}',
            'overflow_tag': 'LoggingOverflow',
            'separator': ' | ',
            'severity': 'LOW'
        }
        self._graylog_rest_api.put('system/cluster_config/com.airbus_cyber_security.graylog.events.config.LoggingAlertConfig', plugin_configuration)
        notification_definition_identifier = self._graylog_rest_api.create_notification(split_fields=['user'])
        self._graylog_rest_api.create_event_definition(notification_definition_identifier, streams=[stream_input_identifier], backlog_size=50, period=_PERIOD)

        with self._graylog_rest_api.create_gelf_input() as gelf_inputs:
            gelf_inputs.send({'_stream': 'input', '_user': 'a'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            time.sleep(2 * _PERIOD)

            logs = self._graylog.extract_latest_logs(5)
            notification_identifier1 = self._parse_notification_log(logs)

            gelf_inputs.send({'_id': notification_identifier1, '_stream': 'log'})
            gelf_inputs.send({'_stream': 'input', '_user': 'b'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            time.sleep(_PERIOD)

            logs = self._graylog.extract_latest_logs(5)
            notification_identifier2 = self._parse_notification_log(logs)

            self.assertNotEqual(notification_identifier2, notification_identifier1)

    def test_aggregation_should_reuse_the_notification_identifier_when_there_is_a_split_field_with_the_same_value(self):
        stream_input_identifier = self._graylog_rest_api.create_stream_with_rule('input', 'stream', 'input')
        stream_log_identifier = self._graylog_rest_api.create_stream_with_rule('log', 'stream', 'log')
        self._graylog_rest_api.create_stream_with_rule('pop', 'stream', 'pop')
        plugin_configuration = {
            'aggregation_stream': stream_log_identifier,
            'aggregation_time': '10',
            'alert_tag': 'LoggingAlert',
            'field_alert_id': 'id',
            'log_body': 'type: alert\nid: ${logging_alert.id}\nseverity: ${logging_alert.severity}\napp: graylog\nsubject: ${event_definition_title}\nbody: ${event_definition_description}\n${if backlog && backlog[0]} src: ${backlog[0].fields.src_ip}\nsrc_category: ${backlog[0].fields.src_category}\ndest: ${backlog[0].fields.dest_ip}\ndest_category: ${backlog[0].fields.dest_category}\n${end}',
            'overflow_tag': 'LoggingOverflow',
            'separator': ' | ',
            'severity': 'LOW'
        }
        self._graylog_rest_api.put('system/cluster_config/com.airbus_cyber_security.graylog.events.config.LoggingAlertConfig', plugin_configuration)
        notification_definition_identifier = self._graylog_rest_api.create_notification(split_fields=['user'])
        self._graylog_rest_api.create_event_definition(notification_definition_identifier, streams=[stream_input_identifier], period=_PERIOD)

        with self._graylog_rest_api.create_gelf_input() as gelf_inputs:
            gelf_inputs.send({'_stream': 'input', '_user': 'a'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            time.sleep(2 * _PERIOD)

            logs = self._graylog.extract_latest_logs(5)
            notification_identifier1 = self._parse_notification_log(logs)

            gelf_inputs.send({'_id': notification_identifier1, '_stream': 'log'})
            gelf_inputs.send({'_stream': 'input', '_user': 'a'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            time.sleep(_PERIOD)

            logs = self._graylog.extract_latest_logs(5)
            notification_identifier2 = self._parse_notification_log(logs)

            self.assertEqual(notification_identifier2, notification_identifier1)
