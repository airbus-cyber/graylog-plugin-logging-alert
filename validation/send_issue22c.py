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
# * create event definition
# * Title: BBB
# * Condition Type: Filter & Aggregation
# * Streams: input
# * Search within the last: 5 seconds
# * Execute search every: 5 seconds
# * Add Notification: NNN

# TODO: try to add a test with eventsDefinitionId (needs two event definitions)

import socket
import time

GRAYLOG_INPUT_ADDRESS = ('127.0.01', 12201)
graylog = socket.create_connection(GRAYLOG_INPUT_ADDRESS)

graylog.send('{ "version": "1.1", "host": "example.org", "short_message": "input1", "_stream": "input" }\0'.encode())

print('Messages sent, waiting for 5s')
time.sleep(5)

print('Sending final pop message')
graylog.send('{ "version": "1.1", "host": "example.org", "short_message": "pop", "_stream": "pop" }\0'.encode())
print('Pop sent, waiting for 10s')
time.sleep(10)


# look at the id of the log for AAA and set it as the alert_id here
graylog.send('{ "version": "1.1", "host": "example.org", "short_message": "AAA log reinjected", "_stream": "log", "_alert_id": "01FN62B80CKDMX4KNNF4VS1RQJ-1333398379" }\0'.encode())
graylog.send('{ "version": "1.1", "host": "example.org", "short_message": "input2", "_stream": "input" }\0'.encode())

print('Messages sent, waiting for 5s')
time.sleep(5)

print('Sending final pop message')
graylog.send('{ "version": "1.1", "host": "example.org", "short_message": "pop", "_stream": "pop" }\0'.encode())
print('Pop sent, waiting for 10s')
time.sleep(10)

# => logs for BBB should have different ID than the logs for AAA

