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
import com.airbus_cyber_security.graylog.events.storage.MessagesSearches;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.floreysoft.jmte.Engine;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;
import org.graylog.events.notifications.EventNotificationContext;
import org.graylog.events.notifications.EventNotificationModelData;
import org.graylog.events.processor.EventDefinitionDto;
import org.graylog.events.event.EventDto;
import org.graylog.scheduler.JobTriggerDto;
import org.graylog2.jackson.TypeReferences;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.Tools;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import java.util.Map;
import java.util.Optional;
import java.util.Set;


public class LoggingAlertUtils {

    private static final String MSGS_URL_BEGIN = "/search?rangetype=absolute&from=";
    private static final String MSGS_URL_TO = "&to=";
    private static final String MSGS_URL_STREAM = "&streams=";
    private static final String COMMA_SEPARATOR = "%2C";

    private static final String UNKNOWN = "<unknown>";

    private final Engine templateEngine;

    private final MessagesSearches searches;

    private final ObjectMapper objectMapper;

    public LoggingAlertUtils(ObjectMapper objectMapper, MessagesSearches searches) {
        this.templateEngine = new Engine();
        this.objectMapper = objectMapper;
        this.searches = searches;
    }

    private String getAlertIDWithSuffix(LoggingNotificationConfig config, LoggingAlertConfig generalConfig,
                                       EventNotificationContext ctx, String key) {
        String events_definition_id = ctx.eventDefinition().get().id();
        String suffix = "-" + getHashFromString(events_definition_id + "-" + key);

        String loggingAlertID = null;
        String aggregationStream = generalConfig.accessAggregationStream();

        if (config.aggregationTime() > 0 && aggregationStream != null && !aggregationStream.isEmpty()) {
            int aggregationTime = config.aggregationTime();
            String alertIdentifierFieldName = generalConfig.accessFieldAlertId();
            loggingAlertID = this.searches.getAggregationAlertIdentifier(aggregationTime, alertIdentifierFieldName, aggregationStream, suffix);
        }

        if (loggingAlertID == null || loggingAlertID.isEmpty()) {
            loggingAlertID = ctx.event().id() + suffix;
        }
        return loggingAlertID;
    }

    private static String concatenateSourceStreams(EventDto event) {
        Set<String> setStreams = event.sourceStreams();
        if (setStreams.isEmpty()) {
            return "";
        }
        StringBuilder result = new StringBuilder();
        for (String stream: setStreams) {
            if (result.length() != 0) {
                result.append(COMMA_SEPARATOR);
            }
            result.append(stream);
        }
        return result.toString();
    }

    static String buildSplitFieldsSearchQuery(Iterable<String> splitFields, MessageSummary messageSummary) {
        StringBuilder searchFields = new StringBuilder();
        int i = 0;
        for (String field: splitFields) {
            // TODO should rather do .toString here (try to reproduce, check if there are other casts elsewhere and remove them+add a unit test)
            String valueAggregationField = messageSummary.getField(field).toString();
            String prefix;
            if (i == 0) {
                prefix = "&q=";
            } else {
                prefix = "+AND+";
            }
            if (valueAggregationField != null && !valueAggregationField.isEmpty()) {
                String escapedValue = valueAggregationField.replace("\\", "\\\\");
                escapedValue = escapedValue.replace("\"", "\\\"");
                searchFields.append(prefix + field + "%3A\"" + escapedValue + "\"");
                i++;
            }
        }

        return searchFields.toString();
    }

    public static String getStreamSearchUrl(EventDto event, DateTime timeBeginSearch) {
        DateTimeFormatter timeFormatter = DateTimeFormat.forPattern("yyy-MM-dd'T'HH'%3A'mm'%3A'ss.SSS'Z'");
        String message_url = MSGS_URL_BEGIN
                + timeBeginSearch.toString(timeFormatter) + MSGS_URL_TO
                + event.eventTimestamp().plusMinutes(1).toString(timeFormatter);
        if (event.sourceStreams().isEmpty()) {
            return message_url;
        }
        return message_url + MSGS_URL_STREAM + concatenateSourceStreams(event);
    }

    private static String getMessagesUrl(EventNotificationContext ctx, LoggingNotificationConfig config, MessageSummary messageSummary,
                                 DateTime timeBeginSearch) {
        DateTimeFormatter timeFormatter = DateTimeFormat.forPattern("yyy-MM-dd'T'HH'%3A'mm'%3A'ss.SSS'Z'");
        EventDto event = ctx.event();
        if (ctx.eventDefinition().isPresent()) {
            DateTime endTime;
            JobTriggerDto jobTrigger = ctx.jobTrigger().get();
            if (jobTrigger.endTime().isPresent()) {
                endTime = jobTrigger.endTime().get().plusMinutes(1);
            } else {
                endTime = jobTrigger.triggeredAt().get().plusMinutes(1);
            }

            /* when the alert is unresolved and the repeat notification is active */
            int timeRange = Tools.getNumber(ctx.jobTrigger().get().createdAt(), 1).intValue();
            if (endTime.isBefore(timeBeginSearch.plusMinutes(timeRange))) {
                endTime = timeBeginSearch.plusMinutes(timeRange);
            }

            DateTime beginTime = timeBeginSearch;

            String search = "";
            String concatStream = concatenateSourceStreams(event);
            if (!concatStream.isEmpty()) {
                search = MSGS_URL_STREAM + concatStream;
            }

            String searchQuery = buildSplitFieldsSearchQuery(config.splitFields(), messageSummary);

            return MSGS_URL_BEGIN
                    + beginTime.toString(timeFormatter) + MSGS_URL_TO
                    + endTime.toString(timeFormatter)
                    + search
                    + searchQuery;
        }

        return getStreamSearchUrl(event, timeBeginSearch);
    }

    private static String getHashFromString(String value) {
        int hash = value.hashCode();
        if (hash < 0) {
            return "a" + Math.abs(hash);
        }
        return String.valueOf(hash);
    }

    public String getAlertID(LoggingNotificationConfig config, LoggingAlertConfig generalConfig, EventNotificationContext ctx) {
        return this.getAlertIDWithSuffix(config, generalConfig, ctx, "");
    }

    public static String getValuesAggregationField(MessageSummary messageSummary, LoggingNotificationConfig config) {
        StringBuilder valuesAggregationField = new StringBuilder();
        for (String field: config.splitFields()) {
            // TODO should probably add a separator: field1=a, field2=ab <=> field1=aa, field2=b!!!
            valuesAggregationField.append(messageSummary.getField(field));
        }
        return valuesAggregationField.toString();
    }

    public Map<String, LoggingAlertFields> getListOfLoggingAlertField(EventNotificationContext ctx,
                                                                      ImmutableList<MessageSummary> backlog,
                                                                      LoggingNotificationConfig config,
                                                                      LoggingAlertConfig generalConfig,
                                                                      DateTime date,
                                                                      String description) {
        Map<String, LoggingAlertFields> listOfLoggingAlertField = Maps.newHashMap();

        for (MessageSummary messageSummary: backlog) {
            String key = getValuesAggregationField(messageSummary, config);
            String messagesUrl = getMessagesUrl(ctx, config, messageSummary, date);

            if (listOfLoggingAlertField.containsKey(key)) {
                continue;
            }

            String loggingAlertID = getAlertIDWithSuffix(config, generalConfig, ctx, key);

            LoggingAlertFields fields = new LoggingAlertFields(loggingAlertID, description, config.severity().getType(), date, messagesUrl);
            listOfLoggingAlertField.put(key, fields);
        }

        return listOfLoggingAlertField;
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

    public String buildMessageBody(String logTemplate, EventNotificationContext context, ImmutableList<MessageSummary> backlog,  LoggingAlertFields loggingAlertFields) {
        Map<String, Object> model = this.getModel(context, backlog, loggingAlertFields);
        return this.templateEngine.transform(logTemplate, model);
    }
}
