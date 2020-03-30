package com.airbus_cyber_security.graylog.config;

import java.util.stream.Stream;

import javax.annotation.Nullable;

import org.graylog.events.contentpack.entities.EventNotificationConfigEntity;
import org.graylog.events.event.EventDto;
import org.graylog.events.notifications.EventNotificationConfig;
import org.graylog.events.notifications.EventNotificationExecutionJob;
import org.graylog.scheduler.JobTriggerData;
import org.graylog2.contentpacks.EntityDescriptorIds;
import org.graylog2.contentpacks.model.entities.references.ValueReference;
import org.graylog2.plugin.rest.ValidationResult;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;

@AutoValue
@JsonTypeName(LoggingAlertConfig.TYPE_NAME)
@JsonDeserialize(builder = LoggingAlertConfig.Builder.class)
public abstract class LoggingAlertConfig implements EventNotificationConfig {

	public static final String TYPE_NAME = "logging-alert-notification";
	
	private static final String FIELD_SEVERITY = "severity";
	private static final String FIELD_SEPARATOR = "separator";
	private static final String FIELD_LOG_BODY = "log_body";
	private static final String FIELD_AGGREGATION_STREAM = "aggregation_stream";
	private static final String FIELD_AGGREGATION_TIME = "aggregation_time";
	private static final String FIELD_LIMIT_OVERFLOW = "limit_overflow";
	private static final String FIELD_FIELD_ALERT_ID = "field_alert_id";
	private static final String FIELD_ALERT_TAG = "alert_tag";
	private static final String FIELD_OVERFLOW_TAG = "overflow_tag";
    
	private static final String FIELD_ALERT_ID = "id";
    private static final String SEPARATOR_TEMPLATE  = "\n";
    private static final String BODY_TEMPLATE =
            "type: alert" + SEPARATOR_TEMPLATE +
                    FIELD_ALERT_ID+ ": ${logging_alert.id}"  + SEPARATOR_TEMPLATE +
                    "severity: ${logging_alert.severity}" + SEPARATOR_TEMPLATE +
                    "app: graylog" + SEPARATOR_TEMPLATE +
                    "subject: ${alertCondition.title}" + SEPARATOR_TEMPLATE +
                    "body: ${check_result.resultDescription}" + SEPARATOR_TEMPLATE +
                    "src: ${message.fields.src_ip}" + SEPARATOR_TEMPLATE +
                    "src_category: ${message.fields.src_category}" + SEPARATOR_TEMPLATE +
                    "dest: ${message.fields.dest_ip}" + SEPARATOR_TEMPLATE +
                    "dest_category: ${message.fields.dest_category}";
	

    @JsonProperty(FIELD_SEVERITY)
    public abstract SeverityType severity();
    
    @JsonProperty(FIELD_SEPARATOR)
    public abstract String separator();
    
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

    @JsonIgnore
    public JobTriggerData toJobTriggerData(EventDto dto) {
    	return EventNotificationExecutionJob.Data.builder().eventDto(dto).build();
    }
    
    @JsonIgnore
    public ValidationResult validate() {
    	final ValidationResult validation = new ValidationResult();
    	if (!isValidSeverity(severity())) {
    		validation.addError(FIELD_SEVERITY, "Severity is invalid format");
    	}
    	if(logBody() == null || logBody().isEmpty()) {
    		validation.addError(FIELD_LOG_BODY, "Log Body cannot be empty");
    	}
    	return validation;
    }
    
    public static Builder builder() {
        return Builder.create();
    }

//    public abstract Builder toBuilder();

    @AutoValue.Builder
    public static abstract class Builder implements EventNotificationConfig.Builder<Builder> {

        @JsonCreator
        public static Builder create() {
        	return new AutoValue_LoggingAlertConfig.Builder()
        			.type(TYPE_NAME)
        			.severity(SeverityType.LOW)
        			.logBody(BODY_TEMPLATE)
        			.separator(" | ")
                    .aggregationStream("*")
        			.aggregationTime(0)
                    .limitOverflow(0)
                    .fieldAlertId(FIELD_ALERT_ID)
        			.alertTag("LoggingAlert")
                    .overflowTag("LoggingOverflow");

        }
    	
    	@JsonProperty(FIELD_SEVERITY)
        public abstract Builder severity(SeverityType severity);
        @JsonProperty(FIELD_SEPARATOR)
        public abstract Builder separator(String separator);
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
        
        public abstract LoggingAlertConfig build();
    }
    
    @Override
    public EventNotificationConfigEntity toContentPackEntity(EntityDescriptorIds entityDescriptorIds) {
    	return LoggingAlertConfigEntity.builder()
    			.severity(severity())
    			.separator(ValueReference.of(separator()))
				.logBody(ValueReference.of(logBody()))
				.aggregationStream(ValueReference.of(aggregationStream()))
				.aggregationTime(aggregationTime())
				.limitOverflow(limitOverflow())
				.fieldAlertId(ValueReference.of(fieldAlertId()))
				.alertTag(ValueReference.of(alertTag()))
				.overflowTag(ValueReference.of(overflowTag()))
    			.build();
    }
    
    private boolean isValidSeverity(SeverityType severityType) {
    	if (severityType == null) {
    		return false;
    	}
    	return true;
    }
}
