#!/usr/bin/python3

# Scenario
# * create GELF TCP input
# * create 3 streams input, pop and log (by filtering the stream field)
# * configure Logging Alert Notification plugging
# ** Default Aggregation Time Range: 10
# ** Alerts Stream: log
# ** Alert ID Field: alert_id
# * create notification
# ** Title: NNN
# ** Notification Type: Logging Alert Notification
# * create event definition
# * Title: AAA
# * Condition Type: Filter & Aggregation
# * Streams: input
# * Search within the last: 5 seconds
# * Execute search every: 5 seconds
# * Add Notification: NNN
# * set a backlog of 50

# TODO: try to add a test with eventsDefinitionId (needs two event definitions)

import socket
import time

GRAYLOG_INPUT_ADDRESS = ('127.0.01', 12201)
graylog = socket.create_connection(GRAYLOG_INPUT_ADDRESS)

graylog.send('{ "version": "1.1", "host": "example.org", "short_message": "input1", "_stream": "input", "_alert_id": "TOTO" }\0'.encode())

print('Messages sent, waiting for 5s')
time.sleep(5)

print('Sending final pop message')
graylog.send('{ "version": "1.1", "host": "example.org", "short_message": "pop", "_stream": "pop" }\0'.encode())
print('Pop sent, waiting for 10s')
time.sleep(10)


# => logs identifier shouldn't be TOTO

