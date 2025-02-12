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
            if (!result.isEmpty()) {
                result.append(COMMA_SEPARATOR);
            }
            result.append(stream);
        }
        return MSGS_URL_STREAM + result.toString();
    }

    private DateTime evaluateEndTime(EventDto event, DateTime beginTime) {
        if (event.timerangeEnd().isEmpty()) {
            return beginTime.plusMinutes(1);
        }
        return event.timerangeEnd().get();
    }

    // TODO simplify code: remove beginTime, replace the full context by event
    public String buildMessagesUrl(EventNotificationContext context, DateTime beginTime) {
        EventDto event = context.event();
        if (event.timerangeStart().isPresent()) {
            beginTime = event.timerangeStart().get();
        }
        DateTime endTime = evaluateEndTime(event, beginTime);
        // TODO review how beginTime/endTime are computed: they do not seem to correspond to the aggregation time range shown when viewing the alert!!
        return MSGS_URL_BEGIN + beginTime.toString(TIME_FORMATTER)
                + MSGS_URL_TO + endTime.toString(TIME_FORMATTER)
                + this.buildSourceStreams(event);
    }
}
