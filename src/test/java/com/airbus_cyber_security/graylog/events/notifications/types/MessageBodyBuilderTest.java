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
import com.google.common.collect.ImmutableList;
import org.graylog.events.event.EventDto;
import org.graylog.events.notifications.DBNotificationService;
import org.graylog.events.notifications.EventNotificationConfig;
import org.graylog.events.notifications.EventNotificationContext;
import org.graylog.events.notifications.EventNotificationSettings;
import org.graylog.events.processor.EventDefinitionDto;
import org.graylog.events.processor.EventProcessorConfig;
import org.graylog.events.processor.aggregation.AggregationEventProcessorConfig;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;

@RunWith(MockitoJUnitRunner.class)
public class MessageBodyBuilderTest {

    private static final String EVENT_DEFINITION_ID = "eventDefinitionId-0";
    private static final String EVENT_ID = "eventId-0";
    private static final String EVENT_ID_1 = "eventId-1";
    private static final String NOTIFICATION_ID = "notificationId-0";

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private DBNotificationService notificationService;

    @Test
    public void testGetAlertIdentifierWithoutAlert() {
        MessageBodyBuilder messageBodyBuilder = new MessageBodyBuilder(objectMapper, notificationService);

        EventNotificationContext context = buildEventNotificationContext();

        String result = messageBodyBuilder.getAlertIdentifier(context);

        Assert.assertTrue(result.startsWith(EVENT_ID));
    }

    private static LoggingAlertConfig buildLoggingAlertConfig() {
        return LoggingAlertConfig.builder()
                .accessSeparator("|")
                .accessLogBody("")
                .accessAggregationTime(60)
                .accessLimitOverflow(500)
                .accessAlertTag("AlertLogging")
                .accessOverflowTag("OverflowAlertTag")
                .build();
    }

    private static EventNotificationContext buildEventNotificationContext() {
        EventProcessorConfig eventProcessorConfig = buildEventProcessorConfig();
        EventNotificationSettings eventNotificationSettings = buildEventNotificationSettings();

        EventDefinitionDto eventDefinition = EventDefinitionDto.builder()
                .id(EVENT_DEFINITION_ID)
                .title(EVENT_DEFINITION_ID)
                .description("")
                .priority(1)
                .alert(true)
                .config(eventProcessorConfig)
                .keySpec(ImmutableList.of())
                .notificationSettings(eventNotificationSettings)
                .build();
        EventDto event = EventDto.builder()
                .id(EVENT_ID)
                .groupByFields(Collections.emptyMap())
                .eventDefinitionId(EVENT_DEFINITION_ID)
                .eventDefinitionType("")
                .eventTimestamp(DateTime.now(DateTimeZone.UTC))
                .processingTimestamp(DateTime.now(DateTimeZone.UTC))
                .streams(new HashSet<>())
                .message("")
                .source("")
                .keyTuple(new ArrayList<>())
                .priority(1)
                .alert(true)
                .fields(Collections.emptyMap())
                .build();

        return EventNotificationContext.builder()
                .eventDefinition(eventDefinition)
                .event(event)
                .notificationId(NOTIFICATION_ID)
                .notificationConfig(buildEventNotificationConfig())
                .build();
    }

    private static EventProcessorConfig buildEventProcessorConfig() {
        return AggregationEventProcessorConfig.builder()
                .query("")
                .streams(new HashSet<>())
                .groupBy(new ArrayList<>())
                .series(new ArrayList<>())
                .conditions(null)
                .executeEveryMs(5000)
                .searchWithinMs(5000)
                .build();
    }

    private static EventNotificationConfig buildEventNotificationConfig() {
        return new EventNotificationConfig.FallbackNotificationConfig();
    }

    private static EventNotificationSettings buildEventNotificationSettings() {
        return EventNotificationSettings.withGracePeriod(5000);
    }
}
