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

package com.airbus_cyber_security.graylog.events.contentpack.entities;

import java.util.Map;
import java.util.Set;

import com.airbus_cyber_security.graylog.events.config.SeverityType;
import com.airbus_cyber_security.graylog.events.notifications.types.LoggingNotificationConfig;
import org.graylog.events.contentpack.entities.EventNotificationConfigEntity;
import org.graylog.events.notifications.EventNotificationConfig;
import org.graylog2.contentpacks.model.entities.EntityDescriptor;
import org.graylog2.contentpacks.model.entities.references.ValueReference;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;

@AutoValue
@JsonTypeName(LoggingNotificationConfig.TYPE_NAME)
@JsonDeserialize(builder = LoggingNotificationConfigEntity.Builder.class)
public abstract class LoggingNotificationConfigEntity implements EventNotificationConfigEntity {

    private static final String FIELD_SEVERITY = "severity";
    private static final String FIELD_SPLIT_FIELDS = "split_fields";
    private static final String FIELD_LOG_BODY = "log_body";
    private static final String FIELD_AGGREGATION_STREAM = "aggregation_stream";
    private static final String FIELD_AGGREGATION_TIME = "aggregation_time";
    private static final String FIELD_LIMIT_OVERFLOW = "limit_overflow";
    private static final String FIELD_FIELD_ALERT_ID = "field_alert_id";
    private static final String FIELD_ALERT_TAG = "alert_tag";
    private static final String FIELD_OVERFLOW_TAG = "overflow_tag";
    private static final String FIELD_SINGLE_MESSAGE = "single_notification";

	@JsonProperty(FIELD_SEVERITY)
    public abstract SeverityType severity();
    
    @JsonProperty(FIELD_SPLIT_FIELDS)
    public abstract Set<String> splitFields();
    
    @JsonProperty(FIELD_LOG_BODY)
    public abstract ValueReference logBody();

    @JsonProperty(FIELD_AGGREGATION_STREAM)
    public abstract ValueReference aggregationStream();
    
    @JsonProperty(FIELD_AGGREGATION_TIME)
    public abstract int aggregationTime();

    @JsonProperty(FIELD_LIMIT_OVERFLOW)
    public abstract int limitOverflow();

    @JsonProperty(FIELD_FIELD_ALERT_ID)
    public abstract ValueReference fieldAlertId();
    
    @JsonProperty(FIELD_ALERT_TAG)
    public abstract ValueReference alertTag();

    @JsonProperty(FIELD_OVERFLOW_TAG)
    public abstract ValueReference overflowTag();

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
                    .type(LoggingNotificationConfig.TYPE_NAME);
        }
    	
    	@JsonProperty(FIELD_SEVERITY)
        public abstract Builder severity(SeverityType severity);
        @JsonProperty(FIELD_SPLIT_FIELDS)
        public abstract Builder splitFields(Set<String> splitFields);
        @JsonProperty(FIELD_LOG_BODY)
        public abstract Builder logBody(ValueReference logBody);
        @JsonProperty(FIELD_AGGREGATION_STREAM)
        public abstract Builder aggregationStream(ValueReference aggregationStream);
        @JsonProperty(FIELD_AGGREGATION_TIME)
        public abstract Builder aggregationTime(int aggregationTime);
        @JsonProperty(FIELD_LIMIT_OVERFLOW)
        public abstract Builder limitOverflow(int limitOverflow);
        @JsonProperty(FIELD_FIELD_ALERT_ID)
        public abstract Builder fieldAlertId(ValueReference fieldAlertId);
        @JsonProperty(FIELD_ALERT_TAG)
        public abstract Builder alertTag(ValueReference alertTag);
        @JsonProperty(FIELD_OVERFLOW_TAG)
        public abstract Builder overflowTag(ValueReference overflowTag);
        @JsonProperty(FIELD_SINGLE_MESSAGE)
        public abstract Builder singleMessage(boolean singleMessage);
        
        public abstract LoggingNotificationConfigEntity build();
    }
    
	@Override
	public EventNotificationConfig toNativeEntity(Map<String, ValueReference> parameters,
			Map<EntityDescriptor, Object> nativeEntities) {
		return LoggingNotificationConfig.builder()
				.severity(severity())
				.splitFields(splitFields())
				.logBody(logBody().asString(parameters))
                .aggregationStream(aggregationStream().asString(parameters))
				.aggregationTime(aggregationTime())
                .limitOverflow(limitOverflow())
                .fieldAlertId(fieldAlertId().asString(parameters))
				.alertTag(alertTag().asString(parameters))
                .overflowTag(overflowTag().asString(parameters))
                .singleMessage(singleMessage())
				.build();
	}
}
