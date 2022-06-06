import time
from graylog_server import GraylogServer
from graylog_rest_api import GraylogRestApi
from graylog_inputs import GraylogInputs


class Graylog:

    def __init__(self):
        self._server = GraylogServer('../runtime')
        self._api = GraylogRestApi()

    def _wait_until_graylog_has_started(self):
        """
        We wait until the default deflector is up, as it seems to be the last operation done on startup
        This might have to change in the future, if graylog changes its ways...
        :return:
        """
        print('Waiting for graylog to start...')

        while True:
            if self._api.default_deflector_is_up():
                break
            time.sleep(1)

    def start(self):
        self._server.start()
        self._wait_until_graylog_has_started()

    def stop(self):
        self._server.stop()

    def extract_latest_logs(self, line_count=None):
        return self._server.extract_latest_logs(line_count)
    
    def start_logs_capture(self):
        self._server.start_logs_capture()
    
    def extract_logs(self):
        return self._server.extract_logs()
    
    def create_notification(self, split_fields=None, single_message=False):
        return self._api.create_notification(split_fields, single_message)

    def create_event_definition(self, notification_identifier, streams=None, backlog_size=None, conditions=None,
                                series=None, period=5):
        self._api.create_event_definition(notification_identifier, streams, backlog_size, conditions, series, period)

    def create_gelf_input(self):
        identifier = self._api.create_gelf_input()
        while not self._api.gelf_input_is_running(identifier):
            time.sleep(.1)
        return GraylogInputs()

    def create_stream_with_rule(self, title, field, value):
        return self._api.create_stream_with_rule(title, field, value)

    def update_plugin_configuration(self, aggregation_stream):
        self._api.update_plugin_configuration(aggregation_stream)
