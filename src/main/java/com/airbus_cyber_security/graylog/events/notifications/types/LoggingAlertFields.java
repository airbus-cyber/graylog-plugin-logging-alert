/*
 * graylog-plugin-logging-alert Source Code
 * Copyright (C) 2018-2020 - Airbus CyberSecurity (SAS) - All rights reserved
 *
 * This file is part of the graylog-plugin-logging-alert GPL Source Code.
 *
 * graylog-plugin-logging-alert Source Code is free software:
 * you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this code.  If not, see <http://www.gnu.org/licenses/>.
 */

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
