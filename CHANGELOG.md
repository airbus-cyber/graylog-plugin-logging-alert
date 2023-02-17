# Change Log

All notable changes to this project will be documented in this file.

## [4.4.0](https://github.com/airbus-cyber/graylog-plugin-logging-alert/compare/4.3.0...4.4.0)
### Changes

## [4.3.0](https://github.com/airbus-cyber/graylog-plugin-logging-alert/compare/4.2.0...4.3.0)
### Features
* Variable `${logging_alert.description}` can now be used in the body template to insert the notification description

## [4.2.0](https://github.com/airbus-cyber/graylog-plugin-logging-alert/compare/4.1.2...4.2.0)
### Features
* Add compatibility with [Graylog 4.3](https://www.graylog.org/post/announcing-graylog-v4-3-graylog-operations-graylog-security)

## [4.1.2](https://github.com/airbus-cyber/graylog-plugin-logging-alert/compare/4.1.1...4.1.2)
### Bug Fixes
* Exception on numeric split fields ([issue #38](https://github.com/airbus-cyber/graylog-plugin-logging-alert/issues/38))
* Missing generation of signed rpms

## [4.1.1](https://github.com/airbus-cyber/graylog-plugin-logging-alert/compare/4.1.0...4.1.1)
### Bug Fixes
* Escape special characters \ and " in graylog url ([issue #14](https://github.com/airbus-cyber/graylog-plugin-logging-alert/issues/14))
* Fixed color of Configure button ([issue #33](https://github.com/airbus-cyber/graylog-plugin-logging-alert/issues/33))

## [4.1.0](https://github.com/airbus-cyber/graylog-plugin-logging-alert/compare/4.0.4...4.1.0)
### Features
* Add compatibility with Graylog 4.2

## [4.0.4](https://github.com/airbus-cyber/graylog-plugin-logging-alert/compare/4.0.3...4.0.4)
### Bug Fixes
* Missing license header

## [4.0.3](https://github.com/airbus-cyber/graylog-plugin-logging-alert/compare/4.0.2...4.0.3)
### Features
* New page for the notification detail ([issue #31](https://github.com/airbus-cyber/graylog-plugin-logging-alert/issues/31))
### Bug Fixes
* Do not reuse the logging identifier when it is already present in messages of the backlog ([issue #22](https://github.com/airbus-cyber/graylog-plugin-logging-alert/issues/22))
* Exception when looking for the logging identifier to perform aggregation ([issue #30](https://github.com/airbus-cyber/graylog-plugin-logging-alert/issues/30))

## [4.0.2](https://github.com/airbus-cyber/graylog-plugin-logging-alert/compare/4.0.1...4.0.2)
### Bug Fixes
* License was incorrectly specified in pom.xml

## [4.0.1](https://github.com/airbus-cyber/graylog-plugin-logging-alert/compare/4.0.0...4.0.1)
### Features
* Changed plugin license to SSPL version 1

## [4.0.0](https://github.com/airbus-cyber/graylog-plugin-logging-alert/compare/2.2.0...4.0.0)
### Features
* Add compatibility with Graylog 4.1

## [2.2.0](https://github.com/airbus-cyber/graylog-plugin-logging-alert/compare/2.1.5...2.2.0)
### Features
* Add compatibility with Graylog 3.3

## [2.1.5](https://github.com/airbus-cyber/graylog-plugin-logging-alert/compare/2.1.4...2.1.5)
### Bug Fixes
* Fix the alert ID generation

## [2.1.4](https://github.com/airbus-cyber/graylog-plugin-logging-alert/compare/2.1.3...2.1.4)
### Bug Fixes
* Fix default configuration when creating notification event

## [2.1.3](https://github.com/airbus-cyber/graylog-plugin-logging-alert/compare/2.1.2...2.1.3)
### Bug Fixes
* Fix logging_alert messages_url when split field

## [2.1.2](https://github.com/airbus-cyber/graylog-plugin-logging-alert/compare/2.1.1...2.1.2)
* Clean code, remove logging_alert.alert_url

## [2.1.1](https://github.com/airbus-cyber/graylog-plugin-logging-alert/compare/2.1.0...2.1.1)
### Bug Fixes
* Fix error when configuration update  

## [2.1.0](https://github.com/airbus-cyber/graylog-plugin-logging-alert/compare/2.0.2...2.1.0)
* Refactoring

## [2.0.2](https://github.com/airbus-cyber/graylog-plugin-logging-alert/compare/2.0.1...2.0.2)
### Bug Fixes
* Add default log body when no general configuration

## [2.0.1](https://github.com/airbus-cyber/graylog-plugin-logging-alert/compare/2.0.0...2.0.1)
### Bug Fixes
* Fix notification error with backlog 
* Fix for single notification
* Fix default template

## [2.0.0](https://github.com/airbus-cyber/graylog-plugin-logging-alert/compare/1.3.0...2.0.0)
### Features
* Add compatibility with Graylog 3.2

## [1.3.0](https://github.com/airbus-cyber/graylog-plugin-logging-alert/compare/1.2.0...1.3.0)
### Features
* Add single message notification

## [1.2.0](https://github.com/airbus-cyber/graylog-plugin-logging-alert/compare/1.1.0...1.2.0)
### Features
* Add compatibility with Graylog 3.0

## [1.1.0](https://github.com/airbus-cyber/graylog-plugin-logging-alert/compare/1.0.1...1.1.0)
### Features
* Add compatibility with Graylog 2.5

## [1.0.1](https://github.com/airbus-cyber/graylog-plugin-logging-alert/compare/1.0.0...1.0.1)
### Bug Fixes
* Fix a notification error when aggregating alerts

## [1.0.0](https://github.com/airbus-cyber/graylog-plugin-logging-alert/tree/1.0.0)
* First release
