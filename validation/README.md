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

## Venv setup

If it doesn't exist yet, create the venv and install dependencies:
```
python3 -m venv venv
source ./venv/bin/activate
pip install -r requirements.txt
```

## Execution
To run:
```
PYTHONPATH=.. python -m unittest --verbose
```
Running only one test:
```
PYTHONPATH=.. python -m unittest test.Test.test_notification_identifier_should_not_be_from_the_message_in_the_backlog_issue22
```

# End-to-end tests

First:
```
cd end_to_end
source venv/bin/activate
```

Running a test and watch it execute:
```
PYTHONPATH=.. pytest --headed -k test_plugin_logging_alert_configuration_save_button_should_close_popup_50
```

To generate a test:
```
playwright codegen http://127.0.0.1:9000/
```
