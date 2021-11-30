#!/usr/bin/python3

# Scenario
# Launch new input GELF TCP
# create Notification
# * Notification Type: Logging Alert Notification
# * Aggregation Time Range: 10
# create Events Definition
# * Condition Type: Filter & Aggregation
# * Search within the last: 5 seconds
# * Execute search every: 5 seconds
# * Add the previously created notification

import socket
import time

GRAYLOG_INPUT_ADDRESS = ('127.0.01', 12201)
graylog = socket.create_connection(GRAYLOG_INPUT_ADDRESS)

#graylog.send('{ "version": "1.1", "host": "example.org", "short_message": "port 80", "_port": 80 }\0'.encode())
#graylog.send('{ "version": "1.1", "host": "example.org", "short_message": "port 80", "_port": 81, "_alert_id": "123" }\0'.encode())
graylog.send('{ "version": "1.1", "host": "example.org", "short_message": "port 80", "_port": 82, "_id": "456" }\0'.encode())


print('Messages sent, waiting for 5s')
time.sleep(5)

print('Sending final pop message')
graylog.send('{ "version": "1.1", "host": "example.org", "short_message": "pop" }\0'.encode())
print('Pop sent, waiting for 10s')
time.sleep(10)

graylog.send('{ "version": "1.1", "host": "example.org", "short_message": "port 80", "_port": 82, "_id": "456" }\0'.encode())


print('Messages sent, waiting for 5s')
time.sleep(5)

print('Sending final pop message')
graylog.send('{ "version": "1.1", "host": "example.org", "short_message": "pop" }\0'.encode())
print('Pop sent, waiting for 10s')
time.sleep(10)

