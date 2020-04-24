package com.airbus_cyber_security.graylog.config;

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

import javax.annotation.Nullable;
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
    private static final String FIELD_AGGREGATION_STREAM = "aggregation_stream";
    private static final String FIELD_AGGREGATION_TIME = "aggregation_time";
    private static final String FIELD_LIMIT_OVERFLOW = "limit_overflow";
    private static final String FIELD_FIELD_ALERT_ID = "field_alert_id";
    private static final String FIELD_ALERT_TAG = "alert_tag";
    private static final String FIELD_OVERFLOW_TAG = "overflow_tag";
    private static final String FIELD_SINGLE_MESSAGE = "single_notification";
    private static final String FIELD_COMMENT = "comment";

    private static final String FIELD_ALERT_ID = "id";
    private static final String SEPARATOR_TEMPLATE  = "\n";
    private static final String BODY_TEMPLATE =
            "alert_id: ${logging_alert.id}"  + SEPARATOR_TEMPLATE +
            "title: ${event_definition_title}" + SEPARATOR_TEMPLATE +
            "description: ${event_definition_description}" + SEPARATOR_TEMPLATE +
            "severity: ${logging_alert.severity}"  + SEPARATOR_TEMPLATE +
            "create_time: ${logging_alert.detect_time}" + SEPARATOR_TEMPLATE +
            "detect_time: ${logging_alert.detect_time}" + SEPARATOR_TEMPLATE +
            "alert_url: http://localhost:8080${logging_alert.alert_url}"  + SEPARATOR_TEMPLATE +
            "messages_url: http://localhost:8080${logging_alert.messages_url}";


    @JsonProperty(FIELD_SEVERITY)
    public abstract SeverityType severity();

    @JsonProperty(FIELD_SPLIT_FIELDS)
    public abstract Set<String> splitFields();

    @JsonProperty(FIELD_LOG_BODY)
    public abstract String logBody();

    @JsonProperty(FIELD_AGGREGATION_STREAM)
    @Nullable
    public abstract String aggregationStream();

    @JsonProperty(FIELD_AGGREGATION_TIME)
    public abstract int aggregationTime();

    @JsonProperty(FIELD_LIMIT_OVERFLOW)
    public abstract int limitOverflow();

    @JsonProperty(FIELD_FIELD_ALERT_ID)
    public abstract String fieldAlertId();

    @JsonProperty(FIELD_ALERT_TAG)
    public abstract String alertTag();

    @JsonProperty(FIELD_OVERFLOW_TAG)
    public abstract String overflowTag();

    @JsonProperty(FIELD_SINGLE_MESSAGE)
    public abstract boolean singleMessage();

    @JsonProperty(FIELD_COMMENT)
    public abstract String comment();

    @JsonIgnore
    public JobTriggerData toJobTriggerData(EventDto dto) {
        return EventNotificationExecutionJob.Data.builder().eventDto(dto).build();
    }

    @JsonIgnore
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
                    .logBody(BODY_TEMPLATE)
                    .splitFields(new HashSet<>())
                    .aggregationStream("*")
                    .aggregationTime(0)
                    .limitOverflow(0)
                    .fieldAlertId(FIELD_ALERT_ID)
                    .alertTag("LoggingAlert")
                    .overflowTag("")
                    .singleMessage(false)
                    .comment("");

        }

        @JsonProperty(FIELD_SEVERITY)
        public abstract Builder severity(SeverityType severity);
        @JsonProperty(FIELD_SPLIT_FIELDS)
        public abstract Builder splitFields(Set<String> splitFields);
        @JsonProperty(FIELD_LOG_BODY)
        public abstract Builder logBody(String logBody);
        @JsonProperty(FIELD_AGGREGATION_STREAM)
        public abstract Builder aggregationStream(String aggregationStream);
        @JsonProperty(FIELD_AGGREGATION_TIME)
        public abstract Builder aggregationTime(int aggregationTime);
        @JsonProperty(FIELD_LIMIT_OVERFLOW)
        public abstract Builder limitOverflow(int limitOverflow);
        @JsonProperty(FIELD_FIELD_ALERT_ID)
        public abstract Builder fieldAlertId(String fieldAlertId);
        @JsonProperty(FIELD_ALERT_TAG)
        public abstract Builder alertTag(String alertTag);
        @JsonProperty(FIELD_OVERFLOW_TAG)
        public abstract Builder overflowTag(String overflowTag);
        @JsonProperty(FIELD_SINGLE_MESSAGE)
        public abstract Builder singleMessage(boolean singleMessage);
        @JsonProperty(FIELD_COMMENT)
        public abstract Builder comment(String comment);

        public abstract LoggingNotificationConfig build();
    }

    @Override
    public EventNotificationConfigEntity toContentPackEntity(EntityDescriptorIds entityDescriptorIds) {
        return LoggingNotificationConfigEntity.builder()
                .severity(severity())
                .splitFields(splitFields())
                .logBody(ValueReference.of(logBody()))
                .aggregationStream(ValueReference.of(aggregationStream()))
                .aggregationTime(aggregationTime())
                .limitOverflow(limitOverflow())
                .fieldAlertId(ValueReference.of(fieldAlertId()))
                .alertTag(ValueReference.of(alertTag()))
                .overflowTag(ValueReference.of(overflowTag()))
                .singleMessage(singleMessage())
                .comment(ValueReference.of(comment()))
                .build();
    }

    private boolean isValidSeverity(SeverityType severityType) {
        if (severityType == null) {
            return false;
        }
        return true;
    }
}
