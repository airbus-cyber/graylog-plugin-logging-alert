package com.airbus_cyber_security.graylog;

import org.joda.time.DateTime;

public class LoggingAlertFields {
	
	private final String id;
	private final String graylog_id;
	private final String severity;
	private final DateTime detect_time;
	private final String alert_url;
	private final String messages_url;
	
	public LoggingAlertFields(String id, String graylog_id, String severity, DateTime detectTime, String alert_url, String messages_url)	{
		this.id = id;
		this.graylog_id = graylog_id;
		this.severity = severity;
		this.detect_time = detectTime;
		this.alert_url = alert_url;
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

	public String getGraylog_id() {
		return graylog_id;
	}
	
	public String getAlert_url() {
		return alert_url;
	}

	public String getMessages_url() {
		return messages_url;
	}

}
