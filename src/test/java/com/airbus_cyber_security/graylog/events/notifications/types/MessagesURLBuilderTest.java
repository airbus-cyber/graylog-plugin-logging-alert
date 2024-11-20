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
import org.graylog2.plugin.Tools;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.graylog2.plugin.streams.Stream;
import org.graylog.events.event.EventOriginContext;

import java.util.HashMap;
import java.util.Map;

public class MessagesURLBuilderTest {

    private MessagesURLBuilder subject;

    private DateTime dummyTime;

    private static final String TEST_NOTIFICATION_ID = "NotificationTestId";

    @Before
    public void setup() {
        this.subject = new MessagesURLBuilder();
        this.dummyTime = DateTime.parse("2023-06-21T14:43:25Z");
    }

    private EventDto.Builder dummyEventBuilder() {
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
                .fields(ImmutableMap.of("field1", "value1", "field2", "value2"));
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

    private EventNotificationContext.Builder dummyContextBuilder() {
        EventNotificationConfig notificationConfig = new EventNotificationConfig.FallbackNotificationConfig();
        EventDefinitionDto eventDefinitionDto = buildDummyEventDefinition();
        EventDto event = dummyEventBuilder()
                .timerangeStart(this.dummyTime)
                .timerangeEnd(this.dummyTime.plusMinutes(1))
                .build();
        return EventNotificationContext.builder()
                .notificationId(TEST_NOTIFICATION_ID)
                .notificationConfig(notificationConfig)
                .eventDefinition(eventDefinitionDto)
                .event(event);
    }

    private JobTriggerDto buildJobTrigger(DateTime jobTriggerTime) {
        return JobTriggerDto.builder()
                .jobDefinitionId("jobDefinitionId")
                .jobDefinitionType("jobDefinitionType")
                .schedule(new JobSchedule.FallbackSchedule())
                .triggeredAt(jobTriggerTime)
                .build();
    }

    private EventNotificationContext buildDummyContext(DateTime jobTriggerTime) {
        JobTriggerDto jobTrigger = buildJobTrigger(jobTriggerTime);
        return dummyContextBuilder()
                .jobTrigger(jobTrigger)
                .build();
    }

    @Test
    public void buildMessagesUrlShouldNotFailWhenSplitFieldIsNotPresent() {
        Map<String, Object> fields = new HashMap<String, Object>();
        fields.put("_id", "identifier");
        EventNotificationContext context = this.buildDummyContext(this.dummyTime);
        this.subject.buildMessagesUrl(context, this.dummyTime);
    }

    @Test
    public void getStreamSearchUrlShouldNotFailWhenThereIsNoJobTrigger() {
        EventNotificationContext context = dummyContextBuilder().build();
        this.subject.buildMessagesUrl(context, this.dummyTime);
    }

    @Test
    public void getStreamSearchUrlShouldNotFailWhenThereIsNoTimerangeStart() {
        EventDto event = dummyEventBuilder().timerangeEnd(this.dummyTime.plusMinutes(1)).build();
        EventNotificationContext context = dummyContextBuilder().event(event).build();
        this.subject.buildMessagesUrl(context, this.dummyTime);
    }

    @Test
    public void getStreamSearchUrlShouldNotFailWhenThereIsNoTimerangeEnd() {
        EventDto event = dummyEventBuilder().timerangeStart(this.dummyTime).build();
        EventNotificationContext context = dummyContextBuilder().event(event).build();
        this.subject.buildMessagesUrl(context, this.dummyTime);
    }
}
