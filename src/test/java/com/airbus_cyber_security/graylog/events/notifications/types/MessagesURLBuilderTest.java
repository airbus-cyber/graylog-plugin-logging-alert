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

// sources of inspiration:
// * org.graylog.events.notifications.NotificationTestData.NotificationTestData
package com.airbus_cyber_security.graylog.events.notifications.types;

import java.util.*;

import org.graylog.events.event.EventDto;
import org.graylog.events.notifications.EventNotificationConfig;
import org.graylog.events.notifications.EventNotificationContext;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import org.graylog.events.notifications.EventNotificationSettings;
import org.graylog.events.processor.EventDefinitionDto;
import org.graylog.events.processor.EventProcessorConfig;
import org.graylog.scheduler.JobSchedule;
import org.graylog.scheduler.JobTriggerDto;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.joda.time.DateTime;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.graylog2.plugin.Tools;
import org.graylog2.plugin.streams.Stream;
import org.graylog.events.event.EventOriginContext;

public class MessagesURLBuilderTest {

    private MessagesURLBuilder subject;

    private DateTime dummyTime;

    private static final String TEST_NOTIFICATION_ID = "NotificationTestId";

    @Before
    public void setup() {
        this.subject = new MessagesURLBuilder();
        this.dummyTime = DateTime.parse("2023-06-21T14:43:25Z");
    }

    private EventDto buildDummyEvent() {
        return EventDto.builder()
                .alert(true)
                .eventDefinitionId("EventDefinitionTestId")
                .eventDefinitionType("notification-test-v1")
                .eventTimestamp(this.dummyTime)
                .processingTimestamp(Tools.nowUTC())
                .id("TEST_NOTIFICATION_ID")
                .streams(ImmutableSet.of(Stream.DEFAULT_EVENTS_STREAM_ID))
                .message("Notification test message triggered from user")
                .source(Stream.DEFAULT_STREAM_ID)
                .keyTuple(ImmutableList.of("testkey"))
                .key("testkey")
                .originContext(EventOriginContext.elasticsearchMessage("testIndex_42", "b5e53442-12bb-4374-90ed-0deadbeefbaz"))
                .priority(2)
                .fields(ImmutableMap.of("field1", "value1", "field2", "value2"))
                .build();
    }

    EventDefinitionDto buildDummyEventDefinition() {
        return EventDefinitionDto.builder()
                .alert(true)
                .id(TEST_NOTIFICATION_ID)
                .title("Event Definition Test Title")
                .description("Event Definition Test Description")
                .config(new EventProcessorConfig.FallbackConfig())
                .fieldSpec(ImmutableMap.of())
                .priority(2)
                .keySpec(ImmutableList.of())
                .notificationSettings(new EventNotificationSettings() {
                                          @Override
                                          public long gracePeriodMs() {
                                              return 0;
                                          }
                                          @Override
                                          // disable to avoid errors in getBacklogForEvent()
                                          public long backlogSize() {
                                              return 0;
                                          }
                                          @Override
                                          public Builder toBuilder() {
                                              return null;
                                          }
                                      }

                ).build();
    }

    private EventNotificationContext buildDummyContext() {
        EventNotificationConfig notificationConfig = new EventNotificationConfig.FallbackNotificationConfig();
        EventDto event = buildDummyEvent();
        EventDefinitionDto eventDefinitionDto = buildDummyEventDefinition();
        return EventNotificationContext.builder()
                .notificationId(TEST_NOTIFICATION_ID)
                .notificationConfig(notificationConfig)
                .event(event)
                .eventDefinition(eventDefinitionDto)
                .build();
    }

    private EventNotificationContext buildDummyContext(DateTime jobTriggerTime) {
        EventNotificationConfig notificationConfig = new EventNotificationConfig.FallbackNotificationConfig();
        EventDto event = buildDummyEvent();
        EventDefinitionDto eventDefinitionDto = buildDummyEventDefinition();
        JobTriggerDto jobTrigger = JobTriggerDto.builder()
                .jobDefinitionId("jobDefinitionId")
                .jobDefinitionType("jobDefinitionType")
                .schedule(new JobSchedule.FallbackSchedule())
                .triggeredAt(jobTriggerTime)
                .build();
        return EventNotificationContext.builder()
                .notificationId(TEST_NOTIFICATION_ID)
                .notificationConfig(notificationConfig)
                .event(event)
                .eventDefinition(eventDefinitionDto)
                .jobTrigger(jobTrigger)
                .build();
    }

    @Test
    public void buildMessagesUrlShouldEscapeBackslash() {
        List<String> splitFields = Collections.singletonList("filename");
        Map<String, Object> fields = new HashMap<String, Object>();
        fields.put("_id", "identifier");
        fields.put("filename", "C:\\File.exe");
        Message message = new Message(fields);
        MessageSummary messageSummary = new MessageSummary("index", message);
        EventNotificationContext context = this.buildDummyContext(this.dummyTime);
        String query = this.subject.buildMessagesUrl(context, splitFields, messageSummary, this.dummyTime);
        Assert.assertEquals("/search?rangetype=absolute&from=2023-06-21T14%3A43%3A25.000Z&to=2023-06-21T14%3A44%3A25.000Z&q=filename%3A\"C:\\\\File.exe\"", query);
    }

    @Test
    public void buildMessagesUrlShouldEscapeDoubleQuotes() {
        List<String> splitFields = Collections.singletonList("key");
        Map<String, Object> fields = new HashMap<String, Object>();
        fields.put("_id", "identifier");
        fields.put("key", "\"");
        Message message = new Message(fields);
        MessageSummary messageSummary = new MessageSummary("index", message);
        EventNotificationContext context = this.buildDummyContext(this.dummyTime);
        String query = this.subject.buildMessagesUrl(context, splitFields, messageSummary, this.dummyTime);
        Assert.assertEquals("/search?rangetype=absolute&from=2023-06-21T14%3A43%3A25.000Z&to=2023-06-21T14%3A44%3A25.000Z&q=key%3A\"\\\"\"", query);
    }

    @Test
    public void buildMessagesUrlShouldNotFailWhenSplitFieldIsInteger() {
        List<String> splitFields = Collections.singletonList("key");
        Map<String, Object> fields = new HashMap<String, Object>();
        fields.put("_id", "identifier");
        fields.put("key", 48);
        Message message = new Message(fields);
        MessageSummary messageSummary = new MessageSummary("index", message);
        EventNotificationContext context = this.buildDummyContext(this.dummyTime);
        this.subject.buildMessagesUrl(context, splitFields, messageSummary, this.dummyTime);
    }

    @Test
    public void buildMessagesUrlShouldNotFailWhenSplitFieldIsNotPresent() {
        List<String> splitFields = Collections.singletonList("key");
        Map<String, Object> fields = new HashMap<String, Object>();
        fields.put("_id", "identifier");
        Message message = new Message(fields);
        MessageSummary messageSummary = new MessageSummary("index", message);
        EventNotificationContext context = this.buildDummyContext(this.dummyTime);
        this.subject.buildMessagesUrl(context, splitFields, messageSummary, this.dummyTime);
    }

    @Test
    public void getStreamSearchUrlShouldComputeTheSameTimeRangeAsbuildMessagesUrlIssue47() {
        List<String> splitFields = Collections.emptyList();
        Map<String, Object> fields = new HashMap<String, Object>();
        fields.put("_id", "identifier");
        Message message = new Message(fields);
        MessageSummary messageSummary = new MessageSummary("index", message);
        DateTime jobTrigger = this.dummyTime.plusMinutes(5);
        EventNotificationContext context = this.buildDummyContext(jobTrigger);
        String query = this.subject.getStreamSearchUrl(context, this.dummyTime);
        String expectedQuery = this.subject.buildMessagesUrl(context, splitFields, messageSummary, this.dummyTime);
        Assert.assertEquals(expectedQuery, query);
    }

    @Test
    public void getStreamSearchUrlShouldNotFailWhenThereIsNoJobTrigger() {
        Map<String, Object> fields = new HashMap<String, Object>();
        fields.put("_id", "identifier");
        EventNotificationContext context = this.buildDummyContext();
        this.subject.getStreamSearchUrl(context, this.dummyTime);
    }
}
