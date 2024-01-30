# Manual scenarios which should be made automatic

## Configuration

* start from http://127.0.0.1:9000/system/configurations

### Save button should not fail
* select Plugins section
* select Logging Alert configuration
* click button edit configuration
* click button Save
* it should not generate an error on request to update the configuration

### Save button should close popup
* select Plugins section
* select Logging Alert configuration
* click button edit configuration
* click button Save
* it should close the popup

### Cancel button should close popup
* select Plugins section
* select Logging Alert configuration
* click button edit configuration
* click button Cancel
* it should close the popup

### Exit cross should close popup
* select Plugins section
* select Logging Alert configuration
* click button edit configuration
* click button exit cross
* it should close the popup

### Cancel button should revert changes
* select Plugins section
* select Logging Alert configuration
* click button edit configuration
* change Line Break Substitution to +
* click button Cancel
* click button edit configuration
* Line Break Substitution should contain |
