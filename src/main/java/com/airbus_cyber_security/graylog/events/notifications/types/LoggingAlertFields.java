package com.airbus_cyber_security.graylog.events.notifications.types;

import org.joda.time.DateTime;

public class LoggingAlertFields {
	
	private final String id;
	private final String severity;
	private final DateTime detect_time;
	private final String messages_url;
	
	public LoggingAlertFields(String id, String severity, DateTime detectTime, String messages_url)	{
		this.id = id;
		this.severity = severity;
		this.detect_time = detectTime;
		this.messages_url = messages_url;
	}

	public String getId() {
		return id;
	}

	public String getSeverity() {
		return severity;
	}

	public DateTime getDetect_time() {
		return detect_time;
	}

	public String getMessages_url() {
		return messages_url;
	}

}
