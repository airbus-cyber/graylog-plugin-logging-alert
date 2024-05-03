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
#   PYTHONPATH=.. python -m unittest test.Test.test_notification_identifier_should_not_be_from_the_message_in_the_backlog_issue22

from unittest import TestCase, skip
import time
from graylog.driver import Driver

_PERIOD = 5


class Test(TestCase):

    def setUp(self) -> None:
        self._subject = Driver('../../runtime')
        self._subject.start()

    def tearDown(self) -> None:
        self._subject.stop()

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
            return log
        return None

    # TODO try to simplify the default log body so that this parsing is easier
    def _parse_notification_identifier(self, log):
        log_sections = log.split(' | ')
        _, identifier = log_sections[2].split(': ')
        return identifier

    def _parse_notification_url(self, log):
        log_sections = log.split(' | ')
        _, url = log_sections[3].split(': ')
        return url

    def _wait_until_notification(self):
        duration = 60
        for i in range(duration):
            time.sleep(1)
            logs = self._subject.extract_logs()
            notification_identifier = self._parse_notification_log(logs)
            if notification_identifier is not None:
                return notification_identifier
        print('All logs')
        print(self._subject._server._extract_all_logs())
        print('Latest logs')
        print(logs)
        self.fail(f'Notification not logged within {duration} seconds')

    def test_process_an_event_should_not_fail_for_a_notification_with_aggregation_issue30(self):
        notification_identifier = self._subject.create_notification()
        self._subject.create_event_definition(notification_identifier, period=_PERIOD)

        with self._subject.create_gelf_input() as gelf_inputs:
            self._subject.start_logs_capture()
            gelf_inputs.send({})
            time.sleep(2*_PERIOD)

            gelf_inputs.send({})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop'})
            # wait long enough for potential exception to occur (even on slow machines)
            time.sleep(2*_PERIOD)
            logs = self._subject.extract_logs()
            self.assertNotIn('ElasticsearchException', logs)

    def test_notification_identifier_should_not_be_from_the_message_in_the_backlog_issue22(self):
        notification_definition_identifier = self._subject.create_notification()
        self._subject.create_event_definition(notification_definition_identifier, backlog_size=50, period=_PERIOD)

        with self._subject.create_gelf_input() as gelf_inputs:
            self._subject.start_logs_capture()
            gelf_inputs.send({'_id': 'message_identifier'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop'})
            notification_identifier = self._parse_notification_identifier(self._wait_until_notification())
            
            self.assertNotEqual(notification_identifier, 'message_identifier')

    def test_set_logging_alert_configuration_should_not_fail(self):
        status_code = self._subject.update_plugin_configuration()
        # TODO should be 200 instead of 202!!
        self.assertEqual(202, status_code)

    # Seems like this test may sometimes block?
    def test_aggregation_should_reuse_the_notification_identifier(self):
        stream_input_identifier = self._subject.create_stream_with_rule('input', 'stream', 'input')
        stream_log_identifier = self._subject.create_stream_with_rule('log', 'stream', 'log')
        self._subject.create_stream_with_rule('pop', 'stream', 'pop')
        self._subject.update_plugin_configuration(stream_log_identifier)
        notification_definition_identifier = self._subject.create_notification()
        self._subject.create_event_definition(notification_definition_identifier, streams=[stream_input_identifier], period=_PERIOD)

        with self._subject.create_gelf_input() as gelf_inputs:
            self._subject.start_logs_capture()
            gelf_inputs.send({'_stream': 'input'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            notification_identifier1 = self._parse_notification_identifier(self._wait_until_notification())

            self._subject.start_logs_capture()
            gelf_inputs.send({'_id': notification_identifier1, '_stream': 'log'})
            gelf_inputs.send({'_stream': 'input'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            notification_identifier2 = self._parse_notification_identifier(self._wait_until_notification())

            self.assertEqual(notification_identifier2, notification_identifier1)

    def test_aggregation_should_not_reuse_identifier_from_different_event_definition(self):
        stream_input1_identifier = self._subject.create_stream_with_rule('input1', 'stream', 'input1')
        stream_input2_identifier = self._subject.create_stream_with_rule('input2', 'stream', 'input2')
        stream_log_identifier = self._subject.create_stream_with_rule('log', 'stream', 'log')
        self._subject.create_stream_with_rule('pop', 'stream', 'pop')
        self._subject.update_plugin_configuration(stream_log_identifier)
        notification_definition_identifier = self._subject.create_notification()
        self._subject.create_event_definition(notification_definition_identifier,
                                                       streams=[stream_input1_identifier],
                                                       period=_PERIOD)
        self._subject.create_event_definition(notification_definition_identifier,
                                                       streams=[stream_input2_identifier],
                                                       period=_PERIOD)

        with self._subject.create_gelf_input() as gelf_inputs:
            self._subject.start_logs_capture()
            gelf_inputs.send({'_stream': 'input1'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            notification_identifier1 = self._parse_notification_identifier(self._wait_until_notification())

            self._subject.start_logs_capture()
            gelf_inputs.send({'_id': notification_identifier1, '_stream': 'log'})
            gelf_inputs.send({'_stream': 'input2'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            # Seems like this test sometimes fails here, should we wait a little bit longer? Or is this truly a bug, a misisng notification?
            notification_identifier2 = self._parse_notification_identifier(self._wait_until_notification())

            self.assertNotEqual(notification_identifier2, notification_identifier1)

    # Seems like this test may sometimes block?
    def test_aggregation_should_not_reuse_the_notification_identifier_when_there_is_a_split_field_with_a_different_value(self):
        stream_input_identifier = self._subject.create_stream_with_rule('input', 'stream', 'input')
        stream_log_identifier = self._subject.create_stream_with_rule('log', 'stream', 'log')
        self._subject.create_stream_with_rule('pop', 'stream', 'pop')
        self._subject.update_plugin_configuration(stream_log_identifier)
        notification_definition_identifier = self._subject.create_notification(split_fields=['user'])
        self._subject.create_event_definition(notification_definition_identifier, streams=[stream_input_identifier], backlog_size=50, period=_PERIOD)

        with self._subject.create_gelf_input() as gelf_inputs:
            self._subject.start_logs_capture()
            gelf_inputs.send({'_stream': 'input', '_user': 'a'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            notification_identifier1 = self._parse_notification_identifier(self._wait_until_notification())

            self._subject.start_logs_capture()
            gelf_inputs.send({'_id': notification_identifier1, '_stream': 'log'})
            gelf_inputs.send({'_stream': 'input', '_user': 'b'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            notification_identifier2 = self._parse_notification_identifier(self._wait_until_notification())

            self.assertNotEqual(notification_identifier2, notification_identifier1)

    # This is the same test as the preceding one, but without a backlog => this may be a bug!!!!
    # TODO try to put this test back...
    @skip
    def test_aggregation_should_not_reuse_the_notification_identifier_when_there_is_a_split_field_with_a_different_value_when_there_is_no_backlog(self):
        stream_input_identifier = self._subject.create_stream_with_rule('input', 'stream', 'input')
        stream_log_identifier = self._subject.create_stream_with_rule('log', 'stream', 'log')
        self._subject.create_stream_with_rule('pop', 'stream', 'pop')
        self._subject.update_plugin_configuration(stream_log_identifier)
        notification_definition_identifier = self._subject.create_notification(split_fields=['user'])
        self._subject.create_event_definition(notification_definition_identifier, streams=[stream_input_identifier], period=_PERIOD)

        with self._subject.create_gelf_input() as gelf_inputs:
            self._subject.start_logs_capture()
            gelf_inputs.send({'_stream': 'input', '_user': 'a'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            notification_identifier1 = self._parse_notification_identifier(self._wait_until_notification())

            self._subject.start_logs_capture()
            gelf_inputs.send({'_id': notification_identifier1, '_stream': 'log'})
            gelf_inputs.send({'_stream': 'input', '_user': 'b'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            notification_identifier2 = self._parse_notification_identifier(self._wait_until_notification())

            self.assertNotEqual(notification_identifier2, notification_identifier1)

    # Seems like this test may sometimes block?
    def test_aggregation_should_reuse_the_notification_identifier_when_there_is_a_split_field_with_the_same_value(self):
        stream_input_identifier = self._subject.create_stream_with_rule('input', 'stream', 'input')
        stream_log_identifier = self._subject.create_stream_with_rule('log', 'stream', 'log')
        self._subject.create_stream_with_rule('pop', 'stream', 'pop')
        self._subject.update_plugin_configuration(stream_log_identifier)
        notification_definition_identifier = self._subject.create_notification(split_fields=['user'])
        self._subject.create_event_definition(notification_definition_identifier, streams=[stream_input_identifier], period=_PERIOD)

        with self._subject.create_gelf_input() as gelf_inputs:
            self._subject.start_logs_capture()
            gelf_inputs.send({'_stream': 'input', '_user': 'a'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            notification_identifier1 = self._parse_notification_identifier(self._wait_until_notification())

            self._subject.start_logs_capture()
            gelf_inputs.send({'_id': notification_identifier1, '_stream': 'log'})
            gelf_inputs.send({'_stream': 'input', '_user': 'a'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            notification_identifier2 = self._parse_notification_identifier(self._wait_until_notification())

            self.assertEqual(notification_identifier2, notification_identifier1)

    def test_aggregation_should_send_several_messages_when_there_is_a_backlog(self):
        stream_input_identifier = self._subject.create_stream_with_rule('input', 'stream', 'input')
        stream_log_identifier = self._subject.create_stream_with_rule('log', 'stream', 'log')
        self._subject.create_stream_with_rule('pop', 'stream', 'pop')
        self._subject.update_plugin_configuration(stream_log_identifier)
        notification_definition_identifier = self._subject.create_notification()
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
        self._subject.create_event_definition(notification_definition_identifier,
                                                       streams=[stream_input_identifier], backlog_size=50,
                                                       conditions=conditions,
                                                       series=[serie],
                                                       period=_PERIOD)

        with self._subject.create_gelf_input() as gelf_inputs:
            self._subject.start_logs_capture()
            gelf_inputs.send({'_stream': 'input'})
            gelf_inputs.send({'_stream': 'input'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            self._wait_until_notification()
            
            logs = self._subject.extract_logs()
            self.assertEqual(self._count_notification_log(logs), 2)

    def test_aggregation_should_send_one_messages_when_there_is_a_backlog_and_single_message(self):
        stream_input_identifier = self._subject.create_stream_with_rule('input', 'stream', 'input')
        stream_log_identifier = self._subject.create_stream_with_rule('log', 'stream', 'log')
        self._subject.create_stream_with_rule('pop', 'stream', 'pop')
        self._subject.update_plugin_configuration(stream_log_identifier)
        notification_definition_identifier = self._subject.create_notification(single_message=True)
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
        self._subject.create_event_definition(notification_definition_identifier,
                                                       streams=[stream_input_identifier], backlog_size=50,
                                                       conditions=conditions,
                                                       series=[serie],
                                                       period=_PERIOD)

        with self._subject.create_gelf_input() as gelf_inputs:
            self._subject.start_logs_capture()
            gelf_inputs.send({'_stream': 'input'})
            gelf_inputs.send({'_stream': 'input'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            self._wait_until_notification()

            logs = self._subject.extract_logs()
            self.assertEqual(self._count_notification_log(logs), 1)

    def test_notifier_should_escape_backslashes_in_messages_url_issue14(self):
        stream_input_identifier = self._subject.create_stream_with_rule('input', 'stream', 'input')
        self._subject.create_stream_with_rule('pop', 'stream', 'pop')
        notification_definition_identifier = self._subject.create_notification(split_fields=['filename'], log_body='type: alert\nid: ${logging_alert.id}\nurl: ${logging_alert.messages_url}')
        self._subject.create_event_definition(notification_definition_identifier, streams=[stream_input_identifier], backlog_size=50)

        with self._subject.create_gelf_input() as gelf_inputs:
            self._subject.start_logs_capture()
            # there are two backslashes here to escape the backslash (in python)
            gelf_inputs.send({'_filename': 'C:\\File.exe', '_stream': 'input'})
            time.sleep(_PERIOD)

            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            log = self._wait_until_notification()

            url = self._parse_notification_url(log)
            self.assertIn('C:\\\\File.exe', url)

    def test_process_an_event_should_not_fail_when_split_field_is_numeric_issue38(self):
        notification_definition_identifier = self._subject.create_notification(split_fields=['dest_port'])
        self._subject.create_event_definition(notification_definition_identifier, backlog_size=50)

        with self._subject.create_gelf_input() as gelf_inputs:
            self._subject.start_logs_capture()
            gelf_inputs.send({'_dest_port': 48})
            time.sleep(_PERIOD)
            gelf_inputs.send({'short_message': 'pop', '_stream': 'pop'})
            # wait long enough for potential exception to occur (even on slow machines)
            time.sleep(2*_PERIOD)
            logs = self._subject.extract_logs()

            self.assertNotIn('ERROR', logs)
