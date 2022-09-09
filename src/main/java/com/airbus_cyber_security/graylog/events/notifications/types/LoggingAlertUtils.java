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
import com.fasterxml.jackson.databind.ObjectMapper;
import com.floreysoft.jmte.Engine;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;
import org.graylog.events.notifications.EventNotificationContext;
import org.graylog.events.notifications.EventNotificationModelData;
import org.graylog.events.processor.EventDefinitionDto;
import org.graylog.events.event.EventDto;
import org.graylog.scheduler.JobTriggerDto;
import org.graylog2.indexer.results.SearchResult;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.indexer.searches.Sorting;
import org.graylog2.jackson.TypeReferences;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.Tools;
import org.graylog2.plugin.indexer.searches.timeranges.AbsoluteRange;
import org.graylog2.plugin.indexer.searches.timeranges.InvalidRangeParametersException;
import org.graylog2.plugin.indexer.searches.timeranges.RelativeRange;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.MessageFormat;
import java.util.Map;
import java.util.Optional;
import java.util.Set;


public class LoggingAlertUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(LoggingAlertUtils.class);

    private static final String MSGS_URL_BEGIN = "/search?rangetype=absolute&from=";
    private static final String MSGS_URL_TO = "&to=";
    private static final String MSGS_URL_STREAM = "&streams=";

    private static final String UNKNOWN = "<unknown>";

    private final Engine templateEngine;

    private final Searches searches;

    private final ObjectMapper objectMapper;

    public LoggingAlertUtils(ObjectMapper objectMapper, Searches searches) {
        this.templateEngine = new Engine();
        this.objectMapper = objectMapper;
        this.searches = searches;
    }

    private String getAggregationAlertID(LoggingNotificationConfig config, LoggingAlertConfig generalConfig, String suffixID) {
        LOGGER.debug("Start of getAggregationAlertID...");
        try {
            RelativeRange relativeRange = RelativeRange.create(config.aggregationTime() * 60);
            final AbsoluteRange range = AbsoluteRange.create(relativeRange.getFrom(), relativeRange.getTo());
            String fieldAlertId = generalConfig.accessFieldAlertId();

            String query = MessageFormat.format("{0}: /.*{1}/", fieldAlertId, suffixID);
            LOGGER.debug("Alert Query: {}", query);

            // Add stream filter
            String filter = "streams:" + generalConfig.accessAggregationStream();
            LOGGER.debug("Alert filter: {}", filter);

            // Execute query
            final SearchResult result = this.searches.search(query, filter,
                    range, 50, 0, new Sorting(Message.FIELD_TIMESTAMP, Sorting.Direction.DESC));

            if (result != null && !result.getResults().isEmpty()) {
                LOGGER.debug(result.getResults().size() + " Alert found");
                // return the first matching alert
                return result.getResults().get(0).getMessage().getField(fieldAlertId).toString();
            }
        } catch (InvalidRangeParametersException e) {
            LOGGER.debug("[getAggregationAlertID] - ERROR!", e);
        }
        return null;
    }

    private String getAlertIDWithSuffix(LoggingNotificationConfig config, LoggingAlertConfig generalConfig,
                                       EventNotificationContext ctx, String key) {
        String events_definition_id = ctx.eventDefinition().get().id();
        String suffix = "-" + getHashFromString(events_definition_id + "-" + key);

        String loggingAlertID = null;
        String aggregationStream = generalConfig.accessAggregationStream();

        if (config.aggregationTime() > 0 && aggregationStream != null && !aggregationStream.isEmpty()) {
            loggingAlertID = getAggregationAlertID(config, generalConfig, suffix);
        }

        if (loggingAlertID == null || loggingAlertID.isEmpty()) {
            loggingAlertID = ctx.event().id() + suffix;
        }
        return loggingAlertID;
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

    public static String getStreamSearchUrl(EventDto event, DateTime timeBeginSearch) {
        DateTimeFormatter timeFormatter = DateTimeFormat.forPattern("yyy-MM-dd'T'HH'%3A'mm'%3A'ss.SSS'Z'");
        String message_url = MSGS_URL_BEGIN
                + timeBeginSearch.toString(timeFormatter) + MSGS_URL_TO
                + event.eventTimestamp().plusMinutes(1).toString(timeFormatter);
        if (event.sourceStreams().isEmpty()) {
            return message_url;
        }
        return message_url + MSGS_URL_STREAM + concatenateStreams(event.sourceStreams());
    }

    String buildSplitFieldsSearchQuery(Iterable<String> splitFields, MessageSummary messageSummary) {
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

    private String getMessagesUrl(EventNotificationContext ctx, LoggingNotificationConfig config, MessageSummary messageSummary,
                                 DateTime timeBeginSearch) {
        DateTimeFormatter timeFormatter = DateTimeFormat.forPattern("yyy-MM-dd'T'HH'%3A'mm'%3A'ss.SSS'Z'");
        EventDto event = ctx.event();
        if (ctx.eventDefinition().isPresent()) {
            DateTime endTime;
            /* If the alert is interval and resolved */
            if (ctx.jobTrigger().isPresent() && ctx.jobTrigger().get().endTime().isPresent()) {
                endTime = ctx.jobTrigger().get().endTime().get().plusMinutes(1);
            } else {
                endTime = ctx.jobTrigger().get().triggeredAt().get().plusMinutes(1);
            }

            /* when the alert is unresolved and the repeat notification is active */
            int timeRange = Tools.getNumber(ctx.jobTrigger().get().createdAt(), 1).intValue();
            if (endTime.isBefore(timeBeginSearch.plusMinutes(timeRange))) {
                endTime = timeBeginSearch.plusMinutes(timeRange);
            }

            DateTime beginTime = timeBeginSearch;

            String search = "";
            String concatStream = concatenateStreams(event.sourceStreams());
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

    public static String getHashFromString(String value) {
        int hash = value.hashCode();
        if (hash < 0) {
            return "a" + Math.abs(hash);
        }
        return String.valueOf(hash);
    }

    public Map<String, LoggingAlertFields> getListOfLoggingAlertField(EventNotificationContext ctx,
                                                                      ImmutableList<MessageSummary> backlog,
                                                                      LoggingNotificationConfig config,
                                                                      LoggingAlertConfig generalConfig,
                                                                      DateTime date) {
        Map<String, LoggingAlertFields> listOfLoggingAlertField = Maps.newHashMap();

        for (MessageSummary messageSummary: backlog) {
            String key = getValuesAggregationField(messageSummary, config);
            String messagesUrl = getMessagesUrl(ctx, config, messageSummary, date);

            if (listOfLoggingAlertField.containsKey(key)) {
                continue;
            }

            String loggingAlertID = getAlertIDWithSuffix(config, generalConfig, ctx, key);

            listOfLoggingAlertField.put(key, new LoggingAlertFields(loggingAlertID, config.severity().getType(), date, messagesUrl));
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

    private static String concatenateStreams(Set<String> setStreams) {
        if (setStreams.isEmpty()) {
            return "";
        }
        StringBuilder result = new StringBuilder();
        for (String stream: setStreams) {
            if (result.length() != 0) {
                result.append("%2C");
            }
            result = result.append(stream);
        }
        return result.toString();
    }
}
