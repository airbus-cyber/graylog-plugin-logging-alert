# Validation

Organization:
* `server` contains tests of the REST API
* `end_to_end` contains end-to-end tests starting with the graphical user interface
* `graylog` contains python library to control Graylog (start/stop docker-compose, send API requests, extract logs)

# Server tests

First:
```
cd server
```

Create the venv (if it doesn't exist yet):
```
python3 -m venv venv
source ./venv/bin/activate
pip install -r requirements.txt
```

To run:
```
source venv/bin/activate
PYTHONPATH=.. pyhon -m unittest --verbose
```

Running only one test:
```
PYTHONPATH=.. python -m unittest test.Test.test_notification_identifier_should_not_be_from_the_message_in_the_backlog_issue22
```

# End-to-end tests

Running a test and watch it execute:
```
cd end_to_end
source venv/bin/activate
PYTHONPATH=.. pytest --headed -k test_plugin_logging_alert_configuration_save_button_should_close_popup_50
```