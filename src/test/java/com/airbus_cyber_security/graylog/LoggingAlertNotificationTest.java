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
package com.airbus_cyber_security.graylog;

import com.airbus_cyber_security.graylog.events.config.LoggingAlertConfig;
import com.airbus_cyber_security.graylog.events.config.SeverityType;
import com.airbus_cyber_security.graylog.events.notifications.types.LoggingAlert;
import com.airbus_cyber_security.graylog.events.notifications.types.LoggingNotificationConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import org.graylog.events.contentpack.entities.EventProcessorConfigEntity;
import org.graylog.events.event.EventDto;
import org.graylog.events.notifications.*;
import org.graylog.events.processor.EventDefinitionDto;
import org.graylog.events.processor.EventProcessorConfig;
import org.graylog.scheduler.JobSchedule;
import org.graylog.scheduler.JobTriggerData;
import org.graylog.scheduler.JobTriggerDto;
import org.graylog.scheduler.JobTriggerLock;
import org.graylog2.contentpacks.EntityDescriptorIds;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.graylog2.plugin.rest.ValidationResult;
import org.joda.time.DateTime;
import org.junit.*;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import java.text.SimpleDateFormat;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

public class LoggingAlertNotificationTest {

    private static final String SEPARATOR_TEMPLATE = " | ";
    private static final String BODY_TEMPLATE =
            "alert_id: ${logging_alert.id}" + SEPARATOR_TEMPLATE +
                    "title: ${event_definition_title}" + SEPARATOR_TEMPLATE +
                    "description: ${event_definition_description}" + SEPARATOR_TEMPLATE +
                    "severity: ${logging_alert.severity}" + SEPARATOR_TEMPLATE +
                    "create_time: ${logging_alert.detect_time}" + SEPARATOR_TEMPLATE +
                    "detect_time: ${logging_alert.detect_time}" + SEPARATOR_TEMPLATE +
                    "messages_url: http://localhost:8080${logging_alert.messages_url}";

    private static final String BODY_TEMPLATE_ADDITIONAL_FIELDS =
            "alert_id: ${logging_alert.id}" + SEPARATOR_TEMPLATE +
                    "title: ${event_definition_title}" + SEPARATOR_TEMPLATE +
                    "description: ${event_definition_description}" + SEPARATOR_TEMPLATE +
                    "severity: ${logging_alert.severity}" + SEPARATOR_TEMPLATE +
                    "create_time: ${logging_alert.detect_time}" + SEPARATOR_TEMPLATE +
                    "detect_time: ${logging_alert.detect_time}" + SEPARATOR_TEMPLATE +
                    "analyzer: Graylog" + SEPARATOR_TEMPLATE +
                    "sensor: ${backlog[0].fields.sensor}" + SEPARATOR_TEMPLATE +
                    "classification: ${backlog[0].fields.classification}" + SEPARATOR_TEMPLATE +
                    "source_ip_address: ${backlog[0].fields.ip_src}" + SEPARATOR_TEMPLATE +
                    "source_port: ${backlog[0].fields.port_src}" + SEPARATOR_TEMPLATE +
                    "target_ip_address: ${backlog[0].fields.ip_dst}" + SEPARATOR_TEMPLATE +
                    "target_port: ${backlog[0].fields.port_dst}" + SEPARATOR_TEMPLATE +
                    "messages_url: http://localhost:8080${logging_alert.messages_url}";

    private static final String BODY_TEMPLATE_ADDITIONAL_FIELDS_SINGLE_MESSAGE =
            "alert_id: ${logging_alert.id}" + SEPARATOR_TEMPLATE +
                    "title: ${event_definition_title}" + SEPARATOR_TEMPLATE +
                    "description: ${event_definition_description}" + SEPARATOR_TEMPLATE +
                    "severity: ${logging_alert.severity}" + SEPARATOR_TEMPLATE +
                    "create_time: ${logging_alert.detect_time}" + SEPARATOR_TEMPLATE +
                    "detect_time: ${logging_alert.detect_time}" + SEPARATOR_TEMPLATE +
                    "analyzer: Graylog" + SEPARATOR_TEMPLATE +
                    "messages_url: http://localhost:8080${logging_alert.messages_url}" + SEPARATOR_TEMPLATE +
                    "${foreach backlog message}" +
                    "sensor: ${message.fields.sensor}" + SEPARATOR_TEMPLATE +
                    "classification: ${message.fields.classification}" + SEPARATOR_TEMPLATE +
                    "source_ip_address: ${message.fields.ip_src}" + SEPARATOR_TEMPLATE +
                    "source_port: ${message.fields.port_src}" + SEPARATOR_TEMPLATE +
                    "target_ip_address: ${message.fields.ip_dst}" + SEPARATOR_TEMPLATE +
                    "target_port: ${message.fields.port_dst}" + SEPARATOR_TEMPLATE +
                    "${end}";

    private static final TestLogger TEST_LOGGER = TestLoggerFactory.getTestLogger("LoggingAlert");

    @Rule
    public final MockitoRule mockitoRule = MockitoJUnit.rule();

    private EventNotificationService notificationCallbackService;

    private LoggingAlert loggingAlert;

    DateTime dateForTest = new DateTime();

    DateTime jobTriggerEndTime = dateForTest.plusMinutes(5);

    @Before
    public void setUp() {
        final ClusterConfigService clusterConfigService = mock(ClusterConfigService.class);
        notificationCallbackService = mock(EventNotificationService.class);
        final ObjectMapper objectMapper = new ObjectMapper();
        final Searches searches = mock(Searches.class);

        LoggingAlertConfig configGeneral = mock(LoggingAlertConfig.class);
        loggingAlert = new LoggingAlert(clusterConfigService, notificationCallbackService, objectMapper, searches);
    }


    private NotificationDto getEmptyLoggingAlertNotification() {
        return NotificationDto.builder()
                .title("")
                .description("")
                .config(LoggingNotificationConfig.Builder.create()
                        .severity(SeverityType.LOW)
                        .splitFields(new HashSet<>())
                        .logBody("")
                        .aggregationTime(0)
                        .alertTag("")
                        .build())
                .build();
    }

    private NotificationDto getLoggingAlertNotification() {
        return NotificationDto.builder()
                .title("Logging Alert Title")
                .description("Logging alert")
                .config(LoggingNotificationConfig.Builder.create()
                        .severity(SeverityType.LOW)
                        .splitFields(new HashSet<>())
                        .logBody("body test ")
                        .aggregationTime(0)
                        .alertTag("alert_tag_test")
                        .build())
                .build();
    }

    @Test
    public void testValidateWithEmptyConfig() {
        final NotificationDto invalidNotification = getEmptyLoggingAlertNotification();
        final ValidationResult validationResult = invalidNotification.validate();
        Assert.assertTrue(validationResult.failed());
    }

    @Test
    public void testValidateLoggingAlertNotification() {
        final NotificationDto validNotification = getLoggingAlertNotification();

        final ValidationResult validationResult = validNotification.validate();
        assertThat(validationResult.failed()).isFalse();
        assertThat(validationResult.getErrors().size()).isEqualTo(0);
    }

    @Test(expected = Exception.class)
    public void testExecuteWithNullContext() {
        loggingAlert.execute(null);
    }

    private String formatDate(DateTime date) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyy-MM-dd'T'HH'%3A'mm'%3A'ss.SSS'Z'");
        return sdf.format(date.toDate());
    }

    private LoggingNotificationConfig getConfig(String bodyTemplate, String tag, boolean single) {
        return LoggingNotificationConfig.builder()
                .aggregationTime(60)
                .alertTag(tag)
                .logBody(bodyTemplate)
                .splitFields(new HashSet<>())
                .severity(SeverityType.LOW)
                .singleMessage(single)
                .build();
    }

    private EventDto getEventDto() {
        return EventDto.builder().eventDefinitionId("event_definition_id")
                .eventDefinitionType("event_definition_type")
                .eventTimestamp(dateForTest)
                .alert(true)
                .fields(new HashMap<>())
                .id("id")
                .key("")
                .keyTuple(new ArrayList<>())
                .message("message")
                .originContext("origin_context")
                .priority(1)
                .processingTimestamp(dateForTest)
                .source("source")
                .sourceStreams(new HashSet<>())
                .streams(new HashSet<>())
                .timerangeEnd(dateForTest)
                .timerangeStart(dateForTest)
                .build();
    }

    private EventDto getEventDtoWithStream() {
        return EventDto.builder().eventDefinitionId("event_definition_id")
                .eventDefinitionType("event_definition_type")
                .eventTimestamp(dateForTest)
                .alert(true)
                .fields(new HashMap<>())
                .id("id")
                .key("")
                .keyTuple(new ArrayList<>())
                .message("message")
                .originContext("origin_context")
                .priority(1)
                .processingTimestamp(dateForTest)
                .source("source")
                .sourceStreams(new HashSet<>(Arrays.asList("stream1", "stream2")))
                .streams(new HashSet<>())
                .timerangeEnd(dateForTest)
                .timerangeStart(dateForTest)
                .build();
    }

    private EventDefinitionDto getEventDefinitionDto() {
        EventProcessorConfig eventProcessorConfig = new EventProcessorConfig() {
            @Override
            public EventProcessorConfigEntity toContentPackEntity(EntityDescriptorIds entityDescriptorIds) {
                return null;
            }

            @Override
            public String type() {
                return "event_definition_type";
            }

            @Override
            public ValidationResult validate() {
                return null;
            }
        };
        return EventDefinitionDto.builder().alert(true)
                .title("event_definition_title")
                .description("event_definition_description")
                .id("event_definition_id")
                .priority(1)
                .config(eventProcessorConfig)
                .keySpec(ImmutableList.<String>builder().build())
                .notificationSettings(EventNotificationSettings.builder().gracePeriodMs(500).build())
                .build();
    }

    private JobTriggerDto getJobTriggerDto() {
        JobTriggerData data = null;
        JobTriggerLock lock = JobTriggerLock.builder().build();
        JobSchedule schedule = new JobSchedule.FallbackSchedule();
        return JobTriggerDto.builder().id("job_trigger_id")
                .createdAt(dateForTest)
                .data(data)
                .endTime(jobTriggerEndTime)
                .jobDefinitionId("job_definition_id")
                .lock(lock)
                .nextTime(dateForTest)
                .schedule(schedule)
                .triggeredAt(dateForTest)
                .build();
    }

    private EventNotificationContext getContext(LoggingNotificationConfig config) {
        return EventNotificationContext.builder()
                .notificationConfig(config)
                .event(getEventDto())
                .eventDefinition(getEventDefinitionDto())
                .notificationId("notification_id")
                .jobTrigger(getJobTriggerDto())
                .build();
    }

    private EventNotificationContext getContextWithStream(LoggingNotificationConfig config) {
        return EventNotificationContext.builder()
                .notificationConfig(config)
                .event(getEventDtoWithStream())
                .eventDefinition(getEventDefinitionDto())
                .notificationId("notification_id")
                .jobTrigger(getJobTriggerDto())
                .build();
    }
}
