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

import org.graylog.events.event.EventDto;
import org.graylog.events.notifications.EventNotificationContext;
import org.graylog.scheduler.JobTriggerDto;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.Tools;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import java.util.Set;

public class MessagesURLBuilder {

    private static final String MSGS_URL_BEGIN = "/search?rangetype=absolute&from=";
    private static final String MSGS_URL_TO = "&to=";
    private static final String MSGS_URL_STREAM = "&streams=";
    private static final String COMMA_SEPARATOR = "%2C";
    private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormat.forPattern("yyy-MM-dd'T'HH'%3A'mm'%3A'ss.SSS'Z'");

    private String concatenateSourceStreams(EventDto event) {
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

    public String getStreamSearchUrl(EventDto event, DateTime timeBeginSearch) {
        String message_url = MSGS_URL_BEGIN
                + timeBeginSearch.toString(TIME_FORMATTER) + MSGS_URL_TO
                + event.eventTimestamp().plusMinutes(1).toString(TIME_FORMATTER);
        if (event.sourceStreams().isEmpty()) {
            return message_url;
        }
        return message_url + MSGS_URL_STREAM + this.concatenateSourceStreams(event);
    }

    private String buildSplitFieldsSearchQuery(Iterable<String> splitFields, MessageSummary messageSummary) {
        StringBuilder searchFields = new StringBuilder();
        int i = 0;
        for (String field: splitFields) {
            Object value = messageSummary.getField(field);
            if (value == null) {
                continue;
            }
            String valueAsString = value.toString();
            if (valueAsString.isEmpty()) {
                continue;
            }
            String prefix;
            if (i == 0) {
                prefix = "&q=";
            } else {
                prefix = "+AND+";
            }
            String escapedValue = valueAsString.replace("\\", "\\\\");
            escapedValue = escapedValue.replace("\"", "\\\"");
            searchFields.append(prefix + field + "%3A\"" + escapedValue + "\"");
            i++;
        }

        return searchFields.toString();
    }

    public String buildMessagesUrl(EventNotificationContext context, Iterable<String> splitFields, MessageSummary messageSummary,
                                    DateTime beginTime) {
        EventDto event = context.event();
        if (!context.eventDefinition().isPresent()) {
            return getStreamSearchUrl(event, beginTime);
        }

        DateTime endTime;
        JobTriggerDto jobTrigger = context.jobTrigger().get();
        if (jobTrigger.endTime().isPresent()) {
            endTime = jobTrigger.endTime().get().plusMinutes(1);
        } else {
            endTime = jobTrigger.triggeredAt().get().plusMinutes(1);
        }

        /* when the alert is unresolved and the repeat notification is active */
        int timeRange = Tools.getNumber(context.jobTrigger().get().createdAt(), 1).intValue();
        if (endTime.isBefore(beginTime.plusMinutes(timeRange))) {
            endTime = beginTime.plusMinutes(timeRange);
        }

        String search = "";
        String concatStream = this.concatenateSourceStreams(event);
        if (!concatStream.isEmpty()) {
            search = MSGS_URL_STREAM + concatStream;
        }

        String searchQuery = this.buildSplitFieldsSearchQuery(splitFields, messageSummary);

        // TODO it should probably be possible to factor this more with code in getStreamSearchUrl
        return MSGS_URL_BEGIN
                + beginTime.toString(TIME_FORMATTER) + MSGS_URL_TO
                + endTime.toString(TIME_FORMATTER)
                + search
                + searchQuery;
    }
}
