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
package com.airbus_cyber_security.graylog.events.config;

public enum SeverityType {
	INFO("info"),
	LOW("low"),
	MEDIUM("medium"),
	HIGH("high");
	
	private final String type;

	SeverityType(String type){
		this.type = type;
	}
	
	public String getType(){
		return type;
	}

	/**
	 * Priority :<br>
	 *  - 1 : Low<br>
	 *  - 2 : Normal<br>
	 *  - 3 : High
	 * @param priority priority value of event definition
	 */
	public static SeverityType getSeverityTypeFromPriority(int priority){
        return switch (priority) {
            case 2 -> MEDIUM;
            case 3 -> HIGH;
            default -> LOW;
        };
	}
}
