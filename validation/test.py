# to create and populate the test venv:
# * python3 -m venv venv
# * source venv/bin/activate
# * pip install -r requirements.txt
# to execute these tests:
# * activate venv
#   source ./venv/bin/activate
# * execute tests
#   python -m unittest --verbose
# * execute only one test
#   python -m unittest test.Test.test_notification_identifier_should_not_be_from_the_message_in_the_backlog_issue22

from unittest import TestCase, skip
import time
from graylog import Graylog

_PERIOD = 5


class Test(TestCase):

    def setUp(self) -> None:
        self._graylog = Graylog()
        self._graylog.start()

    def tearDown(self) -> None:
        self._graylog.stop()

    def _count_notification_log(self, logs):
        result = 0
        for log in logs.splitlines():
            if 'INFO : LoggingAlert' not in log:
                continue
            result += 1
        return result

    def _parse_notification_log(self, logs):
        for log in logs.splitlines():
            if 'INFO : LoggingAlert' not in log:
                continue
            log_sections = log.split(' | ')
            _, identifier = log_sections[1].split(': ')
            return identifier
        return None

    def _wait_until_notification(self):
        notification_identifier = None
        while notification_identifier is None:
            time.sleep(1)
            logs = self._graylog.extract_logs()
            notification_identifier = _parse_notification_log(logs)
        return notification_identifier

    def test_process_an_event_should_not_fail_for_a_notification_with_aggregation_issue30(self):
        notification_identifier = self._graylog.create_notification()
        self._graylog.create_event_definition(notification_identifier, period=_PERIOD)

        with self._graylog.create_gelf_input() as gelf_inputs:
            self._graylog.start_logs_capture()
            gelf_inputs.send({})
            time.sleep(2*_PERIOD)

            gelf_inputs.send({})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop'})
            # wait long enough for potential exception to occur (even on slow machines)
            time.sleep(2*_PERIOD)
            logs = self._graylog.extract_logs()
            self.assertNotIn('ElasticsearchException', logs)

    def test_notification_identifier_should_not_be_from_the_message_in_the_backlog_issue22(self):
        notification_definition_identifier = self._graylog.create_notification()
        self._graylog.create_event_definition(notification_definition_identifier, backlog_size=50, period=_PERIOD)

        with self._graylog.create_gelf_input() as gelf_inputs:
            self._graylog.start_logs_capture()
            gelf_inputs.send({'_id': 'message_identifier'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop'})
            notification_identifier = self._wait_until_notification()
            
            self.assertNotEqual(notification_identifier, 'message_identifier')

    def test_aggregation_should_reuse_the_notification_identifier(self):
        stream_input_identifier = self._graylog.create_stream_with_rule('input', 'stream', 'input')
        stream_log_identifier = self._graylog.create_stream_with_rule('log', 'stream', 'log')
        self._graylog.create_stream_with_rule('pop', 'stream', 'pop')
        self._graylog.update_plugin_configuration(stream_log_identifier)
        notification_definition_identifier = self._graylog.create_notification()
        self._graylog.create_event_definition(notification_definition_identifier, streams=[stream_input_identifier], period=_PERIOD)

        with self._graylog.create_gelf_input() as gelf_inputs:
            self._graylog.start_logs_capture()
            gelf_inputs.send({'_stream': 'input'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            notification_identifier1 = self._wait_until_notification()

            self._graylog.start_logs_capture()
            gelf_inputs.send({'_id': notification_identifier1, '_stream': 'log'})
            gelf_inputs.send({'_stream': 'input'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            notification_identifier2 = self._wait_until_notification()

            self.assertEqual(notification_identifier2, notification_identifier1)

    def test_aggregation_should_not_reuse_identifier_from_different_event_definition(self):
        stream_input1_identifier = self._graylog.create_stream_with_rule('input1', 'stream', 'input1')
        stream_input2_identifier = self._graylog.create_stream_with_rule('input2', 'stream', 'input2')
        stream_log_identifier = self._graylog.create_stream_with_rule('log', 'stream', 'log')
        self._graylog.create_stream_with_rule('pop', 'stream', 'pop')
        self._graylog.update_plugin_configuration(stream_log_identifier)
        notification_definition_identifier = self._graylog.create_notification()
        self._graylog.create_event_definition(notification_definition_identifier,
                                                       streams=[stream_input1_identifier],
                                                       period=_PERIOD)
        self._graylog.create_event_definition(notification_definition_identifier,
                                                       streams=[stream_input2_identifier],
                                                       period=_PERIOD)

        with self._graylog.create_gelf_input() as gelf_inputs:
            self._graylog.start_logs_capture()
            gelf_inputs.send({'_stream': 'input1'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            notification_identifier1 = self._wait_until_notification()

            self._graylog.start_logs_capture()
            gelf_inputs.send({'_id': notification_identifier1, '_stream': 'log'})
            gelf_inputs.send({'_stream': 'input2'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            notification_identifier2 = self._wait_until_notification()

            self.assertNotEqual(notification_identifier2, notification_identifier1)

    def test_aggregation_should_not_reuse_the_notification_identifier_when_there_is_a_split_field_with_a_different_value(self):
        stream_input_identifier = self._graylog.create_stream_with_rule('input', 'stream', 'input')
        stream_log_identifier = self._graylog.create_stream_with_rule('log', 'stream', 'log')
        self._graylog.create_stream_with_rule('pop', 'stream', 'pop')
        self._graylog.update_plugin_configuration(stream_log_identifier)
        notification_definition_identifier = self._graylog.create_notification(split_fields=['user'])
        self._graylog.create_event_definition(notification_definition_identifier, streams=[stream_input_identifier], backlog_size=50, period=_PERIOD)

        with self._graylog.create_gelf_input() as gelf_inputs:
            self._graylog.start_logs_capture()
            gelf_inputs.send({'_stream': 'input', '_user': 'a'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            notification_identifier1 = self._wait_until_notification()

            self._graylog.start_logs_capture()
            gelf_inputs.send({'_id': notification_identifier1, '_stream': 'log'})
            gelf_inputs.send({'_stream': 'input', '_user': 'b'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            notification_identifier2 = self._wait_until_notification()

            self.assertNotEqual(notification_identifier2, notification_identifier1)

    # This is the same test as the preceding one, but without a backlog => this may be a bug!!!!
    # TODO try to put this test back...
    @skip
    def test_aggregation_should_not_reuse_the_notification_identifier_when_there_is_a_split_field_with_a_different_value_when_there_is_no_backlog(self):
        stream_input_identifier = self._graylog.create_stream_with_rule('input', 'stream', 'input')
        stream_log_identifier = self._graylog.create_stream_with_rule('log', 'stream', 'log')
        self._graylog.create_stream_with_rule('pop', 'stream', 'pop')
        self._graylog.update_plugin_configuration(stream_log_identifier)
        notification_definition_identifier = self._graylog.create_notification(split_fields=['user'])
        self._graylog.create_event_definition(notification_definition_identifier, streams=[stream_input_identifier], period=_PERIOD)

        with self._graylog.create_gelf_input() as gelf_inputs:
            self._graylog.start_logs_capture()
            gelf_inputs.send({'_stream': 'input', '_user': 'a'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            notification_identifier1 = self._wait_until_notification()

            self._graylog.start_logs_capture()
            gelf_inputs.send({'_id': notification_identifier1, '_stream': 'log'})
            gelf_inputs.send({'_stream': 'input', '_user': 'b'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            notification_identifier2 = self._wait_until_notification()

            self.assertNotEqual(notification_identifier2, notification_identifier1)

    def test_aggregation_should_reuse_the_notification_identifier_when_there_is_a_split_field_with_the_same_value(self):
        stream_input_identifier = self._graylog.create_stream_with_rule('input', 'stream', 'input')
        stream_log_identifier = self._graylog.create_stream_with_rule('log', 'stream', 'log')
        self._graylog.create_stream_with_rule('pop', 'stream', 'pop')
        self._graylog.update_plugin_configuration(stream_log_identifier)
        notification_definition_identifier = self._graylog.create_notification(split_fields=['user'])
        self._graylog.create_event_definition(notification_definition_identifier, streams=[stream_input_identifier], period=_PERIOD)

        with self._graylog.create_gelf_input() as gelf_inputs:
            self._graylog.start_logs_capture()
            gelf_inputs.send({'_stream': 'input', '_user': 'a'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            notification_identifier1 = self._wait_until_notification()

            self._graylog.start_logs_capture()
            gelf_inputs.send({'_id': notification_identifier1, '_stream': 'log'})
            gelf_inputs.send({'_stream': 'input', '_user': 'a'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            notification_identifier2 = self._wait_until_notification()

            self.assertEqual(notification_identifier2, notification_identifier1)

    # TODO try to put this test back: it works locally, but not on CI (maybe because the machine is not powerful enough)
    #      => should probably take some more log lines/or wait a little bit longer
    @skip
    def test_aggregation_should_send_several_messages_when_there_is_a_backlog(self):
        stream_input_identifier = self._graylog.create_stream_with_rule('input', 'stream', 'input')
        stream_log_identifier = self._graylog.create_stream_with_rule('log', 'stream', 'log')
        self._graylog.create_stream_with_rule('pop', 'stream', 'pop')
        self._graylog.update_plugin_configuration(stream_log_identifier)
        notification_definition_identifier = self._graylog.create_notification()
        conditions = {
            'expression': {
                'expr': '>',
                'left': {
                    'expr': 'number-ref',
                    'ref': 'count-'
                },
                'right': {
                    'expr': 'number',
                    'value': 1
                }
            }
        }
        serie = {
            'function': 'count',
            'id': 'count-'
        }
        self._graylog.create_event_definition(notification_definition_identifier,
                                                       streams=[stream_input_identifier], backlog_size=50,
                                                       conditions=conditions,
                                                       series=[serie],
                                                       period=_PERIOD)

        with self._graylog.create_gelf_input() as gelf_inputs:
            self._graylog.start_logs_capture()
            gelf_inputs.send({'_stream': 'input'})
            gelf_inputs.send({'_stream': 'input'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            time.sleep(_PERIOD)
            logs = self._graylog.extract_logs()
            self.assertEqual(self._count_notification_log(logs), 2)

    # TODO try to put this test back: it works locally, but not on CI (maybe because the machine is not powerful enough)
    #      => should probably take some more log lines/or wait a little bit longer
    @skip
    def test_aggregation_should_send_one_messages_when_there_is_a_backlog_and_single_message(self):
        stream_input_identifier = self._graylog.create_stream_with_rule('input', 'stream', 'input')
        stream_log_identifier = self._graylog.create_stream_with_rule('log', 'stream', 'log')
        self._graylog.create_stream_with_rule('pop', 'stream', 'pop')
        self._graylog.update_plugin_configuration(stream_log_identifier)
        notification_definition_identifier = self._graylog.create_notification(single_message=True)
        conditions = {
            'expression': {
                'expr': '>',
                'left': {
                    'expr': 'number-ref',
                    'ref': 'count-'
                },
                'right': {
                    'expr': 'number',
                    'value': 1
                }
            }
        }
        serie = {
            'function': 'count',
            'id': 'count-'
        }
        self._graylog.create_event_definition(notification_definition_identifier,
                                                       streams=[stream_input_identifier], backlog_size=50,
                                                       conditions=conditions,
                                                       series=[serie],
                                                       period=_PERIOD)

        with self._graylog.create_gelf_input() as gelf_inputs:
            self._graylog.start_logs_capture()
            gelf_inputs.send({'_stream': 'input'})
            gelf_inputs.send({'_stream': 'input'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            time.sleep(_PERIOD)

            logs = self._graylog.extract_logs()
            self.assertEqual(self._count_notification_log(logs), 1)

