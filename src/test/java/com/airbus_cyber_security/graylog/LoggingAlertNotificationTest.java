package com.airbus_cyber_security.graylog;

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
import org.graylog2.indexer.IndexSetRegistry;
import org.graylog2.indexer.indices.Indices;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.rest.ValidationResult;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import com.airbus_cyber_security.graylog.config.LoggingAlertConfig;
import com.airbus_cyber_security.graylog.config.SeverityType;
import org.junit.rules.ExpectedException;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import java.text.SimpleDateFormat;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.groups.Tuple.tuple;
import static org.mockito.Mockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;
import static uk.org.lidalia.slf4jext.Level.INFO;

public class LoggingAlertNotificationTest {

	private static final String SEPARATOR_TEMPLATE = " | ";
	private static final String BODY_TEMPLATE =
			"alert_id: ${logging_alert.id}"  + SEPARATOR_TEMPLATE +
					"severity: ${logging_alert.severity}"  + SEPARATOR_TEMPLATE +
					"create_time: ${logging_alert.detect_time}" + SEPARATOR_TEMPLATE +
					"detect_time: ${logging_alert.detect_time}" + SEPARATOR_TEMPLATE +
					"alert_url: http://localhost:8080${logging_alert.alert_url}"  + SEPARATOR_TEMPLATE +
					"messages_url: http://localhost:8080${logging_alert.messages_url}";

	private static final String BODY_TEMPLATE_ADDITIONAL_FIELDS =
			"alert_id: ${logging_alert.id}"  + SEPARATOR_TEMPLATE +
					"severity: ${logging_alert.severity}" + SEPARATOR_TEMPLATE +
					"create_time: ${logging_alert.detect_time}" + SEPARATOR_TEMPLATE +
					"detect_time: ${logging_alert.detect_time}" + SEPARATOR_TEMPLATE +
					"analyzer: Graylog" + SEPARATOR_TEMPLATE +
					"sensor: ${backlog[0].fields.sensor}" + SEPARATOR_TEMPLATE +
					"classification: ${backlog[0].fields.classification}" + SEPARATOR_TEMPLATE +
					"source_command: ${backlog[0].fields.cmd_src}" + SEPARATOR_TEMPLATE +
					"source_file_name: ${backlog[0].fields.file_src}" + SEPARATOR_TEMPLATE +
					"source_host_name: ${backlog[0].fields.host_src}" + SEPARATOR_TEMPLATE +
					"source_ip_address: ${backlog[0].fields.ip_src}" + SEPARATOR_TEMPLATE +
					"source_mac_address: ${backlog[0].fields.mac_src}" + SEPARATOR_TEMPLATE +
					"source_port: ${backlog[0].fields.port_src}" + SEPARATOR_TEMPLATE +
					"source_process: ${backlog[0].fields.process_src}" + SEPARATOR_TEMPLATE +
					"source_service_name: ${backlog[0].fields.service_src}" + SEPARATOR_TEMPLATE +
					"source_tool: ${backlog[0].fields.tool_src}" + SEPARATOR_TEMPLATE +
					"source_url: ${backlog[0].fields.url_src}" + SEPARATOR_TEMPLATE +
					"source_user_name: ${backlog[0].fields.user_src}" + SEPARATOR_TEMPLATE +
					"source_user_privileges: ${backlog[0].fields.user_role_src}" + SEPARATOR_TEMPLATE +
					"source_user_unique_identifier: ${backlog[0].fields.uid_src}" + SEPARATOR_TEMPLATE +
					"target_command: ${backlog[0].fields.cmd_dst}" + SEPARATOR_TEMPLATE +
					"target_file_name: ${backlog[0].fields.file_dst}" + SEPARATOR_TEMPLATE +
					"target_host_name: ${backlog[0].fields.host_dst}" + SEPARATOR_TEMPLATE +
					"target_ip_address: ${backlog[0].fields.ip_dst}" + SEPARATOR_TEMPLATE +
					"target_mac_address: ${backlog[0].fields.mac_dst}" + SEPARATOR_TEMPLATE +
					"target_port: ${backlog[0].fields.port_dst}" + SEPARATOR_TEMPLATE +
					"target_process: ${backlog[0].fields.process_dst}" + SEPARATOR_TEMPLATE +
					"target_service_name: ${backlog[0].fields.service_dst}" + SEPARATOR_TEMPLATE +
					"target_tool: ${backlog[0].fields.tool_dst}" + SEPARATOR_TEMPLATE +
					"target_url: ${backlog[0].fields.url_dst}" + SEPARATOR_TEMPLATE +
					"target_user_name: ${backlog[0].fields.user_dst}" + SEPARATOR_TEMPLATE +
					"target_user_privileges: ${backlog[0].fields.user_role_dst}" + SEPARATOR_TEMPLATE +
					"target_user_unique_identifier: ${backlog[0].fields.uid_dst}" + SEPARATOR_TEMPLATE +
					"file_name: ${backlog[0].fields.filename}" + SEPARATOR_TEMPLATE +
					"file_hash: ${backlog[0].fields.filehash}" + SEPARATOR_TEMPLATE +
					"file_size: ${backlog[0].fields.filesize}" + SEPARATOR_TEMPLATE +
					"file_type: ${backlog[0].fields.filetype}" + SEPARATOR_TEMPLATE +
					"alert_url: http://localhost:8080${logging_alert.alert_url}"  + SEPARATOR_TEMPLATE +
					"messages_url: http://localhost:8080${logging_alert.messages_url}";

	private static final TestLogger TEST_LOGGER = TestLoggerFactory.getTestLogger("LoggingAlert");
	private static final TestLogger TEST_LOGGER_OVERFLOW = TestLoggerFactory.getTestLogger("LoggingOverflow");

	@Rule
	public ExpectedException expectedException = ExpectedException.none();

	@Rule
	public final MockitoRule mockitoRule = MockitoJUnit.rule();

	private EventNotificationService notificationCallbackService;

	private LoggingAlert loggingAlert;

	DateTime dateForTest = new DateTime();

	DateTime jobTriggerEndTime = dateForTest.plusMinutes(5);

	@Before
	public void setUp() {
		notificationCallbackService = mock(EventNotificationService.class);
		final ObjectMapper objectMapper = new ObjectMapper();
		final Searches searches = mock(Searches.class);
		final Indices indices = mock(Indices.class);
		final IndexSetRegistry indexSetRegistry = mock(IndexSetRegistry.class);
		loggingAlert = new LoggingAlert(notificationCallbackService, objectMapper, searches, indices, indexSetRegistry);

	}


	private NotificationDto getEmptyLoggingAlertNotification() {
		return NotificationDto.builder()
				.title("")
				.description("")
				.config(LoggingAlertConfig.Builder.create()
						.severity(SeverityType.LOW)
						.separator("")
						.logBody("")
						.aggregationStream("")
						.aggregationTime(0)
						.limitOverflow(0)
						.fieldAlertId("")
						.alertTag("")
						.overflowTag("")
						.build())
				.build();
	}

	private NotificationDto getLoggingAlertNotification() {
		return NotificationDto.builder()
				.title("Logging Alert Title")
				.description("Logging alert")
				.config(LoggingAlertConfig.Builder.create()
						.severity(SeverityType.LOW)
						.separator(" | ")
						.logBody("body test ")
						.aggregationStream("Stream test")
						.aggregationTime(0)
						.limitOverflow(0)
						.fieldAlertId("alert_id")
						.alertTag("alert_tag_test")
						.overflowTag("overflow_tag_test")
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
	public void testExecuteWithNullContext() throws EventNotificationException {
		loggingAlert.execute(null);
	}

	@Test
	public void testExecuteWithContext() throws EventNotificationException {
		LoggingAlertConfig config = getConfig(BODY_TEMPLATE);
		//list of MessageSummary
		final ImmutableList<MessageSummary> messageSummaries = ImmutableList.of(
				new MessageSummary("graylog_1", new Message("Test message 1", "source1", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC)))/*,
				new MessageSummary("graylog_2", new Message("Test message 2", "source2", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC)))*/
		);
		EventNotificationContext context = getContext(config);
		when(notificationCallbackService.getBacklogForEvent(context)).thenReturn(messageSummaries);
		loggingAlert.execute(context);

		assertThat(TEST_LOGGER.getLoggingEvents()).extracting("level", "message").contains(
				tuple(INFO, "alert_id: "+context.event().eventDefinitionId() + " | "
						+ "severity: low | create_time: 2017-09-06T17:00:00.000Z | detect_time: 2017-09-06T17:00:00.000Z | "
						+ "alert_url: http://localhost:8080/event/"+ context.event().eventDefinitionId() + " | "
						+ "messages_url: http://localhost:8080"
						+ "/search?rangetype=absolute&from=2017-09-06T17%3A00%3A00.000Z&to=" + formatDate(jobTriggerEndTime.plusMinutes(1)) + "&q=streams%3A" + context.notificationId()));
	}

	@Test
	public void testExecuteWithAdditionalFields() throws EventNotificationException {
		Message message = new Message("Test message 1", "source1", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		message.addField("sensor", "sensor");
		message.addField("classification", "classification");
		message.addField("cmd_src", "cmd_src");
		message.addField("file_src", "file_src");
		message.addField("host_src", "host_src");
		message.addField("ip_src", "ip_src");
		message.addField("mac_src", "mac_src");
		message.addField("port_src", "port_src");
		message.addField("process_src", "process_src");
		message.addField("service_src", "service_src");
		message.addField("tool_src", "tool_src");
		message.addField("url_src", "url_src");
		message.addField("user_src", "user_src");
		message.addField("user_role_src", "user_role_src");
		message.addField("uid_src", "uid_src");
		message.addField("cmd_dst", "cmd_dst");
		message.addField("file_dst", "file_dst");
		message.addField("host_dst", "host_dst");
		message.addField("ip_dst", "ip_dst");
		message.addField("mac_dst", "mac_dst");
		message.addField("port_dst", "port_dst");
		message.addField("process_dst", "process_dst");
		message.addField("service_dst", "service_dst");
		message.addField("tool_dst", "tool_dst");
		message.addField("url_dst", "url_dst");
		message.addField("user_dst", "user_dst");
		message.addField("user_role_dst", "user_role_dst");
		message.addField("uid_dst ", "uid_dst");
		message.addField("filename", "filename");
		message.addField("filehash", "filehash");
		message.addField("filesize", "filesize");
		message.addField("filetype", "filetype");

		final ImmutableList<MessageSummary> messageSummaries = ImmutableList.of(
				new MessageSummary("graylog_1", message));

		LoggingAlertConfig config = getConfig(BODY_TEMPLATE_ADDITIONAL_FIELDS);

		EventNotificationContext context = getContext(config);
		when(notificationCallbackService.getBacklogForEvent(context)).thenReturn(messageSummaries);
		loggingAlert.execute(context);

		assertThat(TEST_LOGGER.getLoggingEvents()).extracting("level", "message").contains(
				tuple(INFO, "alert_id: "+context.event().eventDefinitionId() + " | "
						+ "severity: low | create_time: 2017-09-06T17:00:00.000Z | detect_time: 2017-09-06T17:00:00.000Z | "
						+ "analyzer: Graylog | sensor: sensor | classification: classification | "
						+ "source_command: cmd_src | source_file_name: file_src | source_host_name: host_src | source_ip_address: ip_src | "
						+ "source_mac_address: mac_src | source_port: port_src | source_process: process_src | source_service_name: service_src | "
						+ "source_tool: tool_src | source_url: url_src | source_user_name: user_src | source_user_privileges: user_role_src | "
						+ "source_user_unique_identifier: uid_src | target_command: cmd_dst | target_file_name: file_dst | "
						+ "target_host_name: host_dst | target_ip_address: ip_dst | target_mac_address: mac_dst | target_port: port_dst | "
						+ "target_process: process_dst | target_service_name: service_dst | target_tool: tool_dst | target_url: url_dst | "
						+ "target_user_name: user_dst | target_user_privileges: user_role_dst | target_user_unique_identifier: uid_dst | "
						+ "file_name: filename | file_hash: filehash | file_size: filesize | file_type: filetype | "
						+ "alert_url: http://localhost:8080/event/" + context.event().eventDefinitionId() + " | "
						+ "messages_url: http://localhost:8080"
						+ "/search?rangetype=absolute&from=2017-09-06T17%3A00%3A00.000Z&to=" + formatDate(jobTriggerEndTime.plusMinutes(1))
						+ "&q=streams%3A" + context.notificationId()));
	}

	private String formatDate(DateTime date) {
		SimpleDateFormat sdf = new SimpleDateFormat("yyy-MM-dd'T'HH'%3A'mm'%3A'ss.SSS'Z'");
		return sdf.format(date.toDate());
	}

	private LoggingAlertConfig getConfig(String bodyTemplate) {
		return LoggingAlertConfig.builder()
				.aggregationStream("aggregation_stream")
				.aggregationTime(60)
				.alertTag("LoggingAlert")
				.fieldAlertId("field_alert_id")
				.limitOverflow(0)
				.logBody(bodyTemplate)
				.overflowTag("overflow_tag")
				.separator(" | ")
				.severity(SeverityType.LOW)
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

	private EventNotificationContext getContext(LoggingAlertConfig config) {
		return EventNotificationContext.builder()
				.notificationConfig(config)
				.event(getEventDto())
				.eventDefinition(getEventDefinitionDto())
				.notificationId("notification_id")
				.jobTrigger(getJobTriggerDto())
				.build();
	}
}
