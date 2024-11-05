# Logging Alert Plugin for Graylog

[![Continuous Integration](https://github.com/airbus-cyber/graylog-plugin-logging-alert/actions/workflows/ci.yml/badge.svg)](https://github.com/airbus-cyber/graylog-plugin-logging-alert/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-SSPL-green)](https://www.mongodb.com/licensing/server-side-public-license)
[![GitHub Release](https://img.shields.io/github/v/release/airbus-cyber/graylog-plugin-logging-alert)](https://github.com/airbus-cyber/graylog-plugin-logging-alert/releases)

#### Alert notification plugin for Graylog to generate log messages from alerts

The alert notification generate a log message when an alert is triggered.

Perfect for example to record alerts as internal log messages in Graylog itself using the [Internal Logs Input Plugin for Graylog](https://github.com/graylog-labs/graylog-plugin-internal-logs). Thus you can create a stream to receive and manage alerts.

Also perfect for example to forward alerts via log messages to a Security Incident Response Platform.

Please also take note that if message field values are included in the log message template and these values vary based on the messages that triggered the alert, then multiple log messages may be generated per alert.

Alert example recorded as an internal log message:

![](https://raw.githubusercontent.com/airbus-cyber/graylog-plugin-logging-alert/master/images/alert.png)

## Version Compatibility

| Plugin Version | Graylog Version |
|----------------|-----------------|
| 6.1.0          | 6.1.x           |
| 6.0.0          | 6.0.x           |
| 5.1.x          | \>=5.1.9        |
| 5.0.x          | 5.0.x           |
| 4.3.x          | 4.3.x           |
| 4.2.x          | 4.3.x           |
| 4.1.x          | 4.2.x           |
| 4.0.x          | 4.1.x           |
| 2.2.x          | 3.3.x           |
| 2.1.x          | 3.2.x           |
| 2.0.x          | 3.2.x           |
| 1.3.x          | 3.0.x           |
| 1.2.x          | 3.0.x           |
| 1.1.x          | 2.5.x           |
| 1.0.x          | 2.4.x           |

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

You can also configure the **Log Content** to log the information you want. 
Please see the [Graylog Documentation](https://go2docs.graylog.org/4-x/interacting_with_your_log_data/notifications.html#DataAvailabletoNotifications)

Some plugin-specific fields values can be added to the log content.

| Plugin-specific Fields     | Description                                             |
|----------------------------|---------------------------------------------------------|
| logging_alert.id           | ID of the alert                                         |
| logging_alert.severity     | Severity of the alert                                   |
| logging_alert.detect_time  | Timestamp of the first message that triggered the alert |
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

This project requires Java 17 JDK.

* Clone this repository.
* Clone [graylog2-server](https://github.com/Graylog2/graylog2-server) repository next to this repository.
* Build Graylog2-server with `./mvnw compile -DskipTests=true` (in graylog2-server folder)
* Run `./mvnw package` to build a JAR file (in this project folder).
* Optional: Run `./mvnw org.vafer:jdeb:jdeb` and `./mvnw rpm:rpm` to create a DEB and RPM package respectively.
* Copy generated JAR file in target directory to your Graylog plugin directory.
* Restart the Graylog.

A docker to build can be generated from [Dockerfile](https://github.com/airbus-cyber/graylog-plugin-logging-alert/blob/master/build_docker/Dockerfile).

## License

This plugin is released under version 1 of the [Server Side Public License (SSPL)](LICENSE).
