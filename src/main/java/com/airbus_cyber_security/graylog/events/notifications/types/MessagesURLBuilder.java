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

    private String buildSourceStreams(EventDto event) {
        Set<String> sourceStreams = event.sourceStreams();
        if (sourceStreams.isEmpty()) {
            return "";
        }
        StringBuilder result = new StringBuilder();
        for (String stream: sourceStreams) {
            if (result.length() != 0) {
                result.append(COMMA_SEPARATOR);
            }
            result.append(stream);
        }
        return MSGS_URL_STREAM + result.toString();
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

    private DateTime evaluateEndTime(EventNotificationContext context, DateTime beginTime) {
        DateTime endTime;
        // TODO should handle the case where the jobTrigger is not present
        //      this can happen in the notification edition page when testing the notification
        //      in this case, maybe use event.eventTimestamp().plusMinutes(1) as endTime (as was done before)
        JobTriggerDto jobTrigger = context.jobTrigger().get();
        if (jobTrigger.endTime().isPresent()) {
            endTime = jobTrigger.endTime().get().plusMinutes(1);
        } else {
            endTime = jobTrigger.triggeredAt().get().plusMinutes(1);
        }

        /* when the alert is unresolved and the repeat notification is active */
        int timeRange = Tools.getNumber(jobTrigger.createdAt(), 1).intValue();
        if (endTime.isBefore(beginTime.plusMinutes(timeRange))) {
            endTime = beginTime.plusMinutes(timeRange);
        }

        return endTime;
    }

    public String getStreamSearchUrl(EventNotificationContext context, DateTime beginTime) {
        DateTime endTime = this.evaluateEndTime(context, beginTime);
        // TODO review how beginTime/endTime are computed: they do not seem to correspond to the aggregation time range shown when viewing the alert!!
        return MSGS_URL_BEGIN + beginTime.toString(TIME_FORMATTER)
                + MSGS_URL_TO + endTime.toString(TIME_FORMATTER)
                + this.buildSourceStreams(context.event());
    }

    public String buildMessagesUrl(EventNotificationContext context, Iterable<String> splitFields, MessageSummary messageSummary,
                                    DateTime beginTime) {
        String result = this.getStreamSearchUrl(context, beginTime);

        return result + this.buildSplitFieldsSearchQuery(splitFields, messageSummary);
    }
}
