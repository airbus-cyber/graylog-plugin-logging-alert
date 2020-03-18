package com.airbus_cyber_security.graylog.config;

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
}
