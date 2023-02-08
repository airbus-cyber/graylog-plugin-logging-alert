/*
 * Copyright (C) 2018 Airbus CyberSecurity (SAS)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Server Side Public License, version 1,
 * as published by MongoDB, Inc.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Server Side Public License for more details.
 *
 * You should have received a copy of the Server Side Public License
 * along with this program. If not, see
 * <http://www.mongodb.com/licensing/server-side-public-license>.
 */
package com.airbus_cyber_security.graylog.events.notifications.types;

import org.joda.time.DateTime;

public class LoggingAlertFields {
	
	private final String id;
	private final String description;
	private final String severity;
	private final DateTime detect_time;
	private final String messages_url;

	public LoggingAlertFields(String id, String description, String severity, DateTime detectTime, String messages_url)	{
		this.id = id;
		this.description = description;
		this.severity = severity;
		this.detect_time = detectTime;
		this.messages_url = messages_url;
	}

	public String getId() {
		return id;
	}

	public String getDescription() {
		return this.description;
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
