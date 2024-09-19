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

import com.airbus_cyber_security.graylog.events.config.LoggingAlertConfig;
import com.airbus_cyber_security.graylog.events.config.SeverityType;
import com.airbus_cyber_security.graylog.events.storage.MessagesSearches;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.floreysoft.jmte.Engine;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;
import org.graylog.events.notifications.EventNotificationContext;
import org.graylog.events.notifications.EventNotificationModelData;
import org.graylog.events.processor.EventDefinitionDto;
import org.graylog.scheduler.JobTriggerDto;
import org.graylog2.jackson.TypeReferences;
import org.graylog2.plugin.MessageSummary;
import org.joda.time.DateTime;

import jakarta.inject.Inject;
import java.util.Map;
import java.util.Optional;


public class MessageBodyBuilder {

    private static final String UNKNOWN = "<unknown>";

    private final Engine templateEngine;

    private final MessagesSearches searches;

    private final ObjectMapper objectMapper;

    private final Map<String, LoggingAlertFields> loggingAlertFieldsCache;

    private final MessagesURLBuilder messagesURLBuilder;

    @Inject
    public MessageBodyBuilder(ObjectMapper objectMapper, MessagesSearches searches) {
        this.templateEngine = new Engine();
        this.objectMapper = objectMapper;
        this.searches = searches;
        this.loggingAlertFieldsCache = Maps.newHashMap();
        this.messagesURLBuilder = new MessagesURLBuilder();
    }

    private String getAlertIDWithSuffix(int aggregationTime, LoggingAlertConfig generalConfig,
                                       EventNotificationContext context, String key) {
        String events_definition_id = context.eventDefinition().get().id();
        String suffix = "-" + getHashFromString(events_definition_id + "-" + key);

        String loggingAlertID = null;
        String aggregationStream = generalConfig.accessAggregationStream();

        if (aggregationTime > 0 && aggregationStream != null && !aggregationStream.isEmpty()) {
            String alertIdentifierFieldName = generalConfig.accessFieldAlertId();
            loggingAlertID = this.searches.getAggregationAlertIdentifier(aggregationTime, alertIdentifierFieldName, aggregationStream, suffix);
        }

        if (loggingAlertID == null || loggingAlertID.isEmpty()) {
            loggingAlertID = context.event().id() + suffix;
        }
        return loggingAlertID;
    }

    private String getHashFromString(String value) {
        int hash = value.hashCode();
        if (hash < 0) {
            hash = -hash;
            return "a" + hash;
        }
        return String.valueOf(hash);
    }

    private String getAlertID(int aggregationTime, LoggingAlertConfig generalConfig, EventNotificationContext context) {
        return this.getAlertIDWithSuffix(aggregationTime, generalConfig, context, "");
    }

    private String getValuesAggregationField(MessageSummary messageSummary, LoggingNotificationConfig config) {
        StringBuilder valuesAggregationField = new StringBuilder();
        for (String field: config.splitFields()) {
            // TODO should probably add a separator: field1=a, field2=ab <=> field1=aa, field2=b!!!
            valuesAggregationField.append(messageSummary.getField(field));
        }
        return valuesAggregationField.toString();
    }

    private LoggingAlertFields buildLoggingAlertFields(EventNotificationContext context, LoggingNotificationConfig config, LoggingAlertConfig generalConfig, DateTime date, MessageSummary messageSummary) {
        String key = getValuesAggregationField(messageSummary, config);
        LoggingAlertFields fields = this.loggingAlertFieldsCache.get(key);
        if (fields != null) {
            return fields;
        }

        String messagesUrl = this.messagesURLBuilder.buildMessagesUrl(context, config.splitFields(), messageSummary, date);
        String loggingAlertID = getAlertIDWithSuffix(config.aggregationTime(), generalConfig, context, key);

        String severity = SeverityType.LOW.getType();
        if(context.eventDefinition().isPresent()) {
            severity = SeverityType.getSeverityTypeFromPriority(context.eventDefinition().get().priority()).getType();
        }

        fields = new LoggingAlertFields(loggingAlertID, severity, date, messagesUrl);
        this.loggingAlertFieldsCache.put(key, fields);
        return fields;
    }

    private Map<String, Object> getModel(EventNotificationContext context, ImmutableList<MessageSummary> backlog,  LoggingAlertFields loggingAlertFields) {
        Optional<EventDefinitionDto> definitionDto = context.eventDefinition();
        Optional<JobTriggerDto> jobTriggerDto = context.jobTrigger();
        EventNotificationModelData modelData = EventNotificationModelData.builder()
                .eventDefinitionId(definitionDto.map(EventDefinitionDto::id).orElse(UNKNOWN))
                .eventDefinitionType(definitionDto.map(d -> d.config().type()).orElse(UNKNOWN))
                .eventDefinitionTitle(definitionDto.map(EventDefinitionDto::title).orElse(UNKNOWN))
                .eventDefinitionDescription(definitionDto.map(EventDefinitionDto::description).orElse(UNKNOWN))
                .jobDefinitionId(jobTriggerDto.map(JobTriggerDto::jobDefinitionId).orElse(UNKNOWN))
                .jobTriggerId(jobTriggerDto.map(JobTriggerDto::id).orElse(UNKNOWN))
                .event(context.event())
                .backlog(backlog)
                .build();
        Map<String, Object> model = this.objectMapper.convertValue(modelData, TypeReferences.MAP_STRING_OBJECT);
        model.put("logging_alert", loggingAlertFields);
        return model;
    }

    private String buildMessageBody(String logTemplate, EventNotificationContext context, ImmutableList<MessageSummary> backlog,  LoggingAlertFields loggingAlertFields) {
        Map<String, Object> model = this.getModel(context, backlog, loggingAlertFields);
        return this.templateEngine.transform(logTemplate, model);
    }

    public String buildMessageBodyForBacklog(String logTemplate, EventNotificationContext context, LoggingNotificationConfig config, LoggingAlertConfig generalConfig, DateTime date, ImmutableList<MessageSummary> backlog) {
        String identifier = this.getAlertID(config.aggregationTime(), generalConfig, context);
        String severity = SeverityType.LOW.getType();
        if(context.eventDefinition().isPresent()) {
            severity = SeverityType.getSeverityTypeFromPriority(context.eventDefinition().get().priority()).getType();
        }
        String messagesURL = this.messagesURLBuilder.getStreamSearchUrl(context, date);
        LoggingAlertFields loggingAlertFields = new LoggingAlertFields(identifier, severity, date, messagesURL);
        return this.buildMessageBody(logTemplate, context, backlog, loggingAlertFields);
    }

    public String buildMessageBodyForMessage(String logTemplate, EventNotificationContext context, LoggingNotificationConfig config, LoggingAlertConfig generalConfig, DateTime date, MessageSummary message) {
        LoggingAlertFields loggingAlertFields = this.buildLoggingAlertFields(context, config, generalConfig, date, message);
        ImmutableList<MessageSummary> backlogWithMessage = new ImmutableList.Builder<MessageSummary>().add(message).build();

        return this.buildMessageBody(logTemplate, context, backlogWithMessage, loggingAlertFields);
    }
}
