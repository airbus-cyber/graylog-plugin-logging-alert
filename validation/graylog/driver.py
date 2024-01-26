import time
from graylog.server import Server
from graylog.rest_api import RestApi
from graylog.server_timeout_error import ServerTimeoutError


class Driver:

    def __init__(self, docker_compose_path):
        self._server = Server(docker_compose_path)
        self._api = RestApi()

    def _wait(self, condition, attempts, sleep_duration=1):
        count = 0
        while not condition():
            time.sleep(sleep_duration)
            count += 1
            if count > attempts:
                print(self._server.extract_all_logs())
                raise ServerTimeoutError()

    def _wait_until_graylog_has_started(self):
        """
        We wait until the default deflector is up, as it seems to be the last operation done on startup
        This might have to change in the future, if graylog changes its ways...
        :return:
        """
        print('Waiting for graylog to start...')
        self._wait(self._api.default_deflector_is_up, 180)

    def start(self):
        self._server.start()
        self._wait_until_graylog_has_started()

    def stop(self):
        self._server.stop()

    def start_logs_capture(self):
        self._server.start_logs_capture()
    
    def extract_logs(self):
        return self._server.extract_logs()
    
    def create_notification(self, **kwargs):
        return self._api.create_notification(**kwargs)

    def create_event_definition(self, notification_identifier, streams=None, backlog_size=None, conditions=None,
                                series=None, period=5):
        self._api.create_event_definition(notification_identifier, streams, backlog_size, conditions, series, period)

    def create_gelf_input(self):
        gelf_input = self._api.create_gelf_input()
        self._wait(gelf_input.is_running, 10, sleep_duration=.1)
        gelf_input.connect()
        return gelf_input

    def create_stream_with_rule(self, title, field, value):
        return self._api.create_stream_with_rule(title, field, value)

    def update_plugin_configuration(self, aggregation_stream):
        self._api.update_plugin_configuration(aggregation_stream)

    def configure_telemetry(self):
        self._api.configure_telemetry()
