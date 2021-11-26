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

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.auto.value.AutoValue;

import javax.annotation.Nullable;

import static org.graylog2.plugin.streams.Stream.DEFAULT_STREAM_ID;

/**
 * This is the general configuration of the plugin (see System/Configurations)
 * It is probably linked to the IHM, just by the configuration in the web index.jsx.
 */
@JsonAutoDetect
@AutoValue
public abstract class LoggingAlertConfig {

    private static final String FIELD_ALERT_ID = "id";
    private static final String SEPARATOR_TEMPLATE  = "\n";
    public static final String BODY_TEMPLATE =
                    "type: alert" + SEPARATOR_TEMPLATE +
                    FIELD_ALERT_ID + ": ${logging_alert.id}"  + SEPARATOR_TEMPLATE +
                    "severity: ${logging_alert.severity}" + SEPARATOR_TEMPLATE +
                    "app: graylog" + SEPARATOR_TEMPLATE +
                    "subject: ${event_definition_title}" + SEPARATOR_TEMPLATE +
                    "body: ${event_definition_description}" + SEPARATOR_TEMPLATE +
                    "${if backlog && backlog[0]} src: ${backlog[0].fields.src_ip}" + SEPARATOR_TEMPLATE +
                    "src_category: ${backlog[0].fields.src_category}" + SEPARATOR_TEMPLATE +
                    "dest: ${backlog[0].fields.dest_ip}" + SEPARATOR_TEMPLATE +
                    "dest_category: ${backlog[0].fields.dest_category}" + SEPARATOR_TEMPLATE +
                    "${end}";


    @JsonProperty("severity")
    public abstract SeverityType accessSeverity();

    @JsonProperty("separator")
    public abstract String accessSeparator();

    @JsonProperty("log_body")
    public abstract String accessLogBody();

    @JsonProperty("aggregation_stream")
    @Nullable
    public abstract String accessAggregationStream();

    @JsonProperty("aggregation_time")
    public abstract int accessAggregationTime();

    @JsonProperty("limit_overflow")
    public abstract int accessLimitOverflow();

    @JsonProperty("field_alert_id")
    public abstract String accessFieldAlertId();

    @JsonProperty("alert_tag")
    public abstract String accessAlertTag();

    @JsonProperty("overflow_tag")
    public abstract String accessOverflowTag();

    @JsonCreator
    public static LoggingAlertConfig create(
            @JsonProperty("severity") SeverityType severity,
            @JsonProperty("separator") String separator,
            @JsonProperty("log_body") String logBody,
            @JsonProperty("aggregation_stream") String aggregationStream,
            @JsonProperty("aggregation_time") int aggregationTime,
            @JsonProperty("limit_overflow") int limitOverflow,
            @JsonProperty("field_alert_id") String fieldAlertId,
            @JsonProperty("alert_tag") String alertTag,
            @JsonProperty("overflow_tag") String overflowTag){
        return builder()
                .accessSeverity(severity)
                .accessSeparator(separator)
                .accessLogBody(logBody)
                .accessAggregationStream(aggregationStream)
                .accessAggregationTime(aggregationTime)
                .accessLimitOverflow(limitOverflow)
                .accessFieldAlertId(fieldAlertId)
                .accessAlertTag(alertTag)
                .accessOverflowTag(overflowTag)
                .build();
    }

    public static LoggingAlertConfig createDefault() {
        return builder()
                .accessSeverity(SeverityType.LOW)
                .accessSeparator(" | ")
                .accessLogBody(BODY_TEMPLATE)
                .accessAggregationStream(DEFAULT_STREAM_ID)
                .accessAggregationTime(0)
                .accessLimitOverflow(0)
                .accessLimitOverflow(0)
                .accessFieldAlertId(FIELD_ALERT_ID)
                .accessAlertTag("LoggingAlert")
                .accessOverflowTag("LoggingOverflow")
                .build();
    }

    public static Builder builder() {
        return new AutoValue_LoggingAlertConfig.Builder();
    }


    public abstract Builder toBuilder();

    @AutoValue.Builder
    public abstract static class Builder {

        public abstract Builder accessSeverity(SeverityType accessSeverity);
        public abstract Builder accessSeparator(String accessSeparator);
        public abstract Builder accessLogBody(String accessLogBody);
        public abstract Builder accessAggregationStream(String accessAggregationStream);
        public abstract Builder accessAggregationTime(int accessAggregationTime);
        public abstract Builder accessLimitOverflow(int accessLimitOverflow);
        public abstract Builder accessFieldAlertId(String accessFieldAlertId);
        public abstract Builder accessAlertTag(String accessAlertTag);
        public abstract Builder accessOverflowTag(String accessOverflowTag);

        public abstract LoggingAlertConfig build();
    }
}
