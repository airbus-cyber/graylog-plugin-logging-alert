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

import com.airbus_cyber_security.graylog.events.config.LoggingAlertConfig;
import com.airbus_cyber_security.graylog.events.config.SeverityType;
import com.airbus_cyber_security.graylog.events.contentpack.entities.LoggingNotificationConfigEntity;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;
import org.graylog.events.contentpack.entities.EventNotificationConfigEntity;
import org.graylog.events.event.EventDto;
import org.graylog.events.notifications.EventNotificationConfig;
import org.graylog.events.notifications.EventNotificationExecutionJob;
import org.graylog.scheduler.JobTriggerData;
import org.graylog2.contentpacks.EntityDescriptorIds;
import org.graylog2.contentpacks.model.entities.references.ValueReference;
import org.graylog2.plugin.rest.ValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Set;

@AutoValue
@JsonTypeName(LoggingNotificationConfig.TYPE_NAME)
@JsonDeserialize(builder = LoggingNotificationConfig.Builder.class)
public abstract class LoggingNotificationConfig implements EventNotificationConfig {
    private static final Logger LOGGER = LoggerFactory.getLogger(LoggingNotificationConfig.class);

    public static final String TYPE_NAME = "logging-alert-notification";

    private static final String FIELD_SEVERITY = "severity";
    private static final String FIELD_SPLIT_FIELDS = "split_fields";
    private static final String FIELD_LOG_BODY = "log_body";
    private static final String FIELD_AGGREGATION_TIME = "aggregation_time";
    private static final String FIELD_ALERT_TAG = "alert_tag";
    private static final String FIELD_SINGLE_MESSAGE = "single_notification";

    @JsonProperty(FIELD_SEVERITY)
    public abstract SeverityType severity();

    @JsonProperty(FIELD_SPLIT_FIELDS)
    public abstract Set<String> splitFields();

    @JsonProperty(FIELD_LOG_BODY)
    public abstract String logBody();

    @JsonProperty(FIELD_AGGREGATION_TIME)
    public abstract int aggregationTime();

    @JsonProperty(FIELD_ALERT_TAG)
    public abstract String alertTag();

    @JsonProperty(FIELD_SINGLE_MESSAGE)
    public abstract boolean singleMessage();

    @JsonIgnore
    @Override
    public JobTriggerData toJobTriggerData(EventDto dto) {
        return EventNotificationExecutionJob.Data.builder().eventDto(dto).build();
    }

    @JsonIgnore
    @Override
    public ValidationResult validate() {
        final ValidationResult validation = new ValidationResult();
        String errorMessage;
        if (!isValidSeverity(severity())) {
            errorMessage = "Severity is invalid format";
            LOGGER.error(errorMessage);
            validation.addError(FIELD_SEVERITY, errorMessage);
        }
        if(logBody() == null || logBody().isEmpty()) {
            errorMessage = "Log Body cannot be empty";
            LOGGER.error(errorMessage);
            validation.addError(FIELD_LOG_BODY, errorMessage);
        }
        return validation;
    }

    public static LoggingNotificationConfig.Builder builder() {
        return LoggingNotificationConfig.Builder.create();
    }

    @AutoValue.Builder
    public static abstract class Builder implements EventNotificationConfig.Builder<LoggingNotificationConfig.Builder> {

        @JsonCreator
        public static Builder create() {
            return new AutoValue_LoggingNotificationConfig.Builder()
                    .type(TYPE_NAME)
                    .severity(SeverityType.LOW)
                    .logBody(LoggingAlertConfig.BODY_TEMPLATE)
                    .splitFields(new HashSet<>())
                    .aggregationTime(0)
                    .alertTag("LoggingAlert")
                    .singleMessage(false);
        }

        @JsonProperty(FIELD_SEVERITY)
        public abstract Builder severity(SeverityType severity);
        @JsonProperty(FIELD_SPLIT_FIELDS)
        public abstract Builder splitFields(Set<String> splitFields);
        @JsonProperty(FIELD_LOG_BODY)
        public abstract Builder logBody(String logBody);
        @JsonProperty(FIELD_AGGREGATION_TIME)
        public abstract Builder aggregationTime(int aggregationTime);
        @JsonProperty(FIELD_ALERT_TAG)
        public abstract Builder alertTag(String alertTag);
        @JsonProperty(FIELD_SINGLE_MESSAGE)
        public abstract Builder singleMessage(boolean singleMessage);

        public abstract LoggingNotificationConfig build();
    }

    @Override
    public EventNotificationConfigEntity toContentPackEntity(EntityDescriptorIds entityDescriptorIds) {
        return LoggingNotificationConfigEntity.builder()
                .severity(severity())
                .splitFields(splitFields())
                .logBody(ValueReference.of(logBody()))
                .aggregationTime(aggregationTime())
                .alertTag(ValueReference.of(alertTag()))
                .singleMessage(singleMessage())
                .build();
    }

    private boolean isValidSeverity(SeverityType severityType) {
        if (severityType == null) {
            return false;
        }
        return true;
    }
}
