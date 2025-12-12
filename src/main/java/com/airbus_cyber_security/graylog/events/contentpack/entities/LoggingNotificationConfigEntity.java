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
package com.airbus_cyber_security.graylog.events.contentpack.entities;

import com.airbus_cyber_security.graylog.events.notifications.types.LoggingNotificationConfig;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;
import org.graylog.events.contentpack.entities.EventNotificationConfigEntity;
import org.graylog.events.notifications.EventNotificationConfig;
import org.graylog2.contentpacks.model.entities.EntityDescriptor;
import org.graylog2.contentpacks.model.entities.references.ValueReference;

import java.util.Map;

@AutoValue
@JsonTypeName(LoggingNotificationConfigEntity.TYPE_NAME)
@JsonDeserialize(builder = LoggingNotificationConfigEntity.Builder.class)
public abstract class LoggingNotificationConfigEntity implements EventNotificationConfigEntity {

    public static final String TYPE_NAME = "logging-alert-notification";

    private static final String FIELD_LOG_BODY = "log_body";
    private static final String FIELD_ALERT_TAG = "alert_tag";
    private static final String FIELD_SINGLE_MESSAGE = "single_notification";
    
    @JsonProperty(FIELD_LOG_BODY)
    public abstract ValueReference logBody();
    
    @JsonProperty(FIELD_ALERT_TAG)
    public abstract ValueReference alertTag();

    @JsonProperty(FIELD_SINGLE_MESSAGE)
    public abstract boolean singleMessage();
    
    public static Builder builder() {
        return Builder.create();
    }

    public abstract Builder toBuilder();
    
    @AutoValue.Builder
    public static abstract class Builder implements EventNotificationConfigEntity.Builder<Builder> {
    	@JsonCreator
        public static Builder create() {
            return new AutoValue_LoggingNotificationConfigEntity.Builder()
                    .type(TYPE_NAME);
        }

        @JsonProperty(FIELD_LOG_BODY)
        public abstract Builder logBody(ValueReference logBody);
        @JsonProperty(FIELD_ALERT_TAG)
        public abstract Builder alertTag(ValueReference alertTag);
        @JsonProperty(FIELD_SINGLE_MESSAGE)
        public abstract Builder singleMessage(boolean singleMessage);
        
        public abstract LoggingNotificationConfigEntity build();
    }
    
	@Override
	public EventNotificationConfig toNativeEntity(Map<String, ValueReference> parameters,
			Map<EntityDescriptor, Object> nativeEntities) {
		return LoggingNotificationConfig.builder()
				.logBody(logBody().asString(parameters))
				.alertTag(alertTag().asString(parameters))
                .singleMessage(singleMessage())
				.build();
	}
}
