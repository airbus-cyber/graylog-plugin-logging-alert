# Logging Alert Plugin for Graylog

[![Build Status](https://travis-ci.org/airbus-cyber/graylog-plugin-logging-alert.svg?branch=master)](https://travis-ci.org/airbus-cyber/graylog-plugin-logging-alert)
[![License](https://img.shields.io/badge/license-GPL--3.0-orange.svg)](https://www.gnu.org/licenses/gpl-3.0.txt)
[![GitHub Release](https://img.shields.io/badge/release-v2.0.1-blue.svg)](https://github.com/airbus-cyber/graylog-plugin-logging-alert/releases)

#### Alert notification plugin for Graylog to generate log messages from alerts

The alert notification generate a log message when an alert is triggered.  

Perfect for example to record alerts as internal log messages in Graylog itself using the [Internal Logs Input Plugin for Graylog](https://github.com/graylog-labs/graylog-plugin-internal-logs). Thus you can create a stream to receive and manage alerts.  

Also perfect for example to forward alerts via log messages to a Security Incident Response Platform.  

Please also take note that if message field values are included in the log message template and these values vary based on the messages that triggered the alert, then multiple log messages may be generated per alert.  

Alert example recorded as an internal log message:

![](https://raw.githubusercontent.com/airbus-cyber/graylog-plugin-logging-alert/master/images/alert.png)

## Version Compatibility

|  Plugin Version | Graylog Version | 
| --------------- | --------------- | 
| 2.0.x           | 3.2.x           | 
| 1.3.x           | 3.0.x           |
| 1.2.x           | 3.0.x           |
| 1.1.x           | 2.5.x           |
| 1.0.x           | 2.4.x           |

## Installation

[Download the plugin](https://github.com/airbus-cyber/graylog-plugin-logging-alert/releases)
and place the `.jar` file in your Graylog plugin directory. The plugin directory
is the `plugins/` folder relative from your `graylog-server` directory by default
and can be configured in your `graylog.conf` file.

Restart `graylog-server` and you are done.

## Usage

### Configure a notification

First you have to select **Logging Alert Notification** as the notification type.

![](https://raw.githubusercontent.com/airbus-cyber/graylog-plugin-logging-alert/master/images/select_notification.png)

Then, in the popup that occurs, you can configure the **Title** of the notification.  

You can configure the **Alert Severity**. You have the choice between 4 levels of severity.  

You can also configure the **Log Content** to log the information you want. Some plugin-specific fields values can be added to the log content.  

| Plugin-specific Fields     | Description                                             |
| -------------------------- | ------------------------------------------------------- |
| logging_alert.id           | ID of the alert                                         |
| logging_alert.severity     | Severity of the alert                                   |
| logging_alert.detect_time  | Timestamp of the first message that triggered the alert |
| logging_alert.alert_url    | URI of the Graylog alert                                |
| logging_alert.messages_url | URI to the retrieve messages that triggered the alert   |

The parameter **Split Fields** allow you to split the alert based on message field values. Thus, a different alert id is generated for each value of one or more message fields.

The parameter **Aggregation Time Range** allow you to aggregate alerts received in the given number of minutes. Thus, the alerts are logged with the same alert id during the time range.

![](https://raw.githubusercontent.com/airbus-cyber/graylog-plugin-logging-alert/master/images/edit_notification.png)

The parameter **Single message** allow you to sent only one notification by alert

![](https://raw.githubusercontent.com/airbus-cyber/graylog-plugin-logging-alert/master/images/edit_notification2.png)

You can optionally add any **Comment** about the configuration of the notification.  


Make sure you also configured alert conditions for the stream so that the alerts are actually triggered.  

### Configure the plugin parameters

Click on **Configure** in the **System / Configurations** section to update the plugin configuration.  
 
In the popup that occurs, you can configure the default value of the parameters that are set when adding a new notification: **Default Alert Severity**, **Default Log Content** and **Default Aggregation Time Range**.  

You can define a **Line Break Substitution** of the log content in order to help parsing log fields and their values. Thus a separator can be inserted between the fields of the log content.  

You can also configure the **Alerts Stream**. This stream must receive the log messages of alerts to enable the alert aggregation feature. Use the [Internal Logs Input Plugin for Graylog](https://github.com/graylog-labs/graylog-plugin-internal-logs) for this purpose.  

You can also set the **Alert ID Field** which is the field that is checked to get the alert id in the log messages of the Alerts Stream.  

You can optionally define an **Overflow Limit**. From this given number of log messages per triggered alert, all the following log messages generated by the notification are tagged as overflow. This limit prevents you from forwarding too many log messages per alert to a Security Incident Response Platform by filtering the log messages according to their tag. For this purpose you can choose the name of the tags: **Alert Tag** and **Overflow Tag**.  

![](https://raw.githubusercontent.com/airbus-cyber/graylog-plugin-logging-alert/master/images/edit_plugin_configuration.png)

## Build

This project is using Maven 3 and requires Java 8 or higher.

* Clone this repository.
* Run `mvn package` to build a JAR file.
* Optional: Run `mvn jdeb:jdeb` and `mvn rpm:rpm` to create a DEB and RPM package respectively.
* Copy generated JAR file in target directory to your Graylog plugin directory.
* Restart the Graylog.

## License

This plugin is released under version 3.0 of the [GNU General Public License](https://www.gnu.org/licenses/gpl-3.0.txt).
