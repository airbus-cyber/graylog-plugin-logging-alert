import subprocess


class GraylogServer:

    def __init__(self, docker_compose_path):
        self._docker_compose_path = docker_compose_path
        self._log_offset = 0

    def start(self):
        subprocess.run(['docker-compose', 'up', '--detach'], cwd=self._docker_compose_path)
    
    def _extract_all_logs(self):
        return subprocess.check_output(['docker-compose', 'logs', '--no-log-prefix', '--no-color', 'graylog'], cwd=self._docker_compose_path, universal_newlines=True)

    def start_logs_capture(self):
        logs = self._extract_all_logs()
        self._log_offset = len(logs)
    
    def extract_logs(self):
        logs = self._extract_all_logs()
        return logs[self._log_offset:]
    
    def extract_latest_logs(self, line_count=None):
        if line_count is None:
            line_count = 'all'
        tail_option = '--tail={}'.format(line_count)
        return subprocess.check_output(['docker-compose', 'logs', tail_option, '--no-log-prefix', '--no-color', 'graylog'], cwd=self._docker_compose_path, universal_newlines=True)

    def stop(self):
        subprocess.run(['docker-compose', 'down'], cwd=self._docker_compose_path)
