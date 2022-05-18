import subprocess


class GraylogServer:

    def __init__(self, docker_compose_path):
        self._docker_compose_path = docker_compose_path

    def start(self):
        subprocess.run(['docker-compose', 'up', '--detach'], cwd=self._docker_compose_path)

    def extract_latest_logs(self, line_count=None):
        if line_count is None:
            line_count = 'all'
        tail_option = '--tail={}'.format(line_count)
        return subprocess.check_output(['docker-compose', 'logs', tail_option, '--no-color', 'graylog'], cwd=self._docker_compose_path, universal_newlines=True)

    def stop(self):
        subprocess.run(['docker-compose', 'down'], cwd=self._docker_compose_path)
