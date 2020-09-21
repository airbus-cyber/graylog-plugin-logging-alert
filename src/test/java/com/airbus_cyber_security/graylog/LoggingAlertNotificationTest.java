package com.airbus_cyber_security.graylog;

import com.airbus_cyber_security.graylog.events.config.LoggingAlertConfig;
import com.airbus_cyber_security.graylog.events.notifications.types.LoggingNotificationConfig;
import com.airbus_cyber_security.graylog.events.notifications.types.LoggingAlert;
import com.airbus_cyber_security.graylog.events.notifications.types.LoggingAlertUtils;
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
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.graylog2.plugin.rest.ValidationResult;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import com.airbus_cyber_security.graylog.events.config.SeverityType;
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
			"title: ${event_definition_title}" + SEPARATOR_TEMPLATE +
			"description: ${event_definition_description}" + SEPARATOR_TEMPLATE +
			"severity: ${logging_alert.severity}"  + SEPARATOR_TEMPLATE +
			"create_time: ${logging_alert.detect_time}" + SEPARATOR_TEMPLATE +
			"detect_time: ${logging_alert.detect_time}" + SEPARATOR_TEMPLATE +
			"messages_url: http://localhost:8080${logging_alert.messages_url}";

	private static final String BODY_TEMPLATE_ADDITIONAL_FIELDS =
			"alert_id: ${logging_alert.id}"  + SEPARATOR_TEMPLATE +
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
			"alert_id: ${logging_alert.id}"  + SEPARATOR_TEMPLATE +
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
	public ExpectedException expectedException = ExpectedException.none();

	@Rule
	public final MockitoRule mockitoRule = MockitoJUnit.rule();

	private EventNotificationService notificationCallbackService;

	private LoggingAlert loggingAlert;

	private LoggingAlertConfig configGeneral;

	DateTime dateForTest = new DateTime();

	DateTime jobTriggerEndTime = dateForTest.plusMinutes(5);

	@Before
	public void setUp() {
		final ClusterConfigService clusterConfigService= mock(ClusterConfigService.class);
		notificationCallbackService = mock(EventNotificationService.class);
		final ObjectMapper objectMapper = new ObjectMapper();
		final Searches searches = mock(Searches.class);
		configGeneral = mock(LoggingAlertConfig.class);
		when(configGeneral.accessSeparator()).thenReturn(" | ");
		when(clusterConfigService.getOrDefault(LoggingAlertConfig.class, LoggingAlertConfig.createDefault())).thenReturn(configGeneral);
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
				.config(LoggingNotificationConfig.Builder.create()
						.severity(SeverityType.LOW)
						.splitFields(new HashSet<>())
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
		LoggingNotificationConfig config = getConfig(BODY_TEMPLATE,"LoggingAlert", false);
		//list of MessageSummary
		final ImmutableList<MessageSummary> messageSummaries = ImmutableList.of(
				new MessageSummary("graylog_1", new Message("Test message 1", "source1", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC)))
		);
		EventNotificationContext context = getContext(config);
		when(notificationCallbackService.getBacklogForEvent(context)).thenReturn(messageSummaries);
		loggingAlert.execute(context);

		assertThat(TEST_LOGGER.getLoggingEvents()).extracting("level", "message").contains(
				tuple(INFO, "alert_id: "+context.event().eventDefinitionId() + " | "
						+ "title: "+context.eventDefinition().get().title() + " | "
						+ "description: "+context.eventDefinition().get().description() + " | "
						+ "severity: low | create_time: 2017-09-06T17:00:00.000Z | detect_time: 2017-09-06T17:00:00.000Z | "
						+ "messages_url: http://localhost:8080"
						+ "/search?rangetype=absolute&from=2017-09-06T17%3A00%3A00.000Z&to=" + formatDate(jobTriggerEndTime.plusMinutes(1))));
	}

	@Test
	public void testExecuteWithContextAndStreams() throws EventNotificationException {
		LoggingNotificationConfig config = getConfig(BODY_TEMPLATE,"LoggingAlert", false);
		//list of MessageSummary
		final ImmutableList<MessageSummary> messageSummaries = ImmutableList.of(
				new MessageSummary("graylog_1", new Message("Test message 1", "source1", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC)))
		);
		EventNotificationContext context = getContextWithStream(config);
		when(notificationCallbackService.getBacklogForEvent(context)).thenReturn(messageSummaries);
		loggingAlert.execute(context);

		String concatStreams = LoggingAlertUtils.getConcatStreams(context.event().sourceStreams());

		assertThat(TEST_LOGGER.getLoggingEvents()).extracting("level", "message").contains(
				tuple(INFO, "alert_id: "+context.event().eventDefinitionId() + " | "
						+ "title: "+context.eventDefinition().get().title() + " | "
						+ "description: "+context.eventDefinition().get().description() + " | "
						+ "severity: low | create_time: 2017-09-06T17:00:00.000Z | detect_time: 2017-09-06T17:00:00.000Z | "
						+ "messages_url: http://localhost:8080"
						+ "/search?rangetype=absolute&from=2017-09-06T17%3A00%3A00.000Z&to=" + formatDate(jobTriggerEndTime.plusMinutes(1)) + "&streams=" + concatStreams));
	}

	@Test
	public void testExecuteWithAdditionalFields() throws EventNotificationException {
		Message message = new Message("Test message 1", "source1", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		message.addField("sensor", "sensor");
		message.addField("classification", "classification");
		message.addField("ip_src", "192.168.2.10");
		message.addField("port_src", "50000");
		message.addField("ip_dst", "192.168.2.20");
		message.addField("port_dst", "60000");

		Message message2 = new Message("Test message 2", "source1", new DateTime(2017, 9, 6, 17, 1, DateTimeZone.UTC));
		message2.addField("sensor", "sensor");
		message2.addField("classification", "classification");
		message2.addField("ip_src", "192.168.2.11");
		message2.addField("port_src", "50001");
		message2.addField("ip_dst", "192.168.2.21");
		message2.addField("port_dst", "60001");
		final ImmutableList<MessageSummary> messageSummaries = ImmutableList.of(
				new MessageSummary("graylog_1", message),
				new MessageSummary("graylog_1", message2));

		String tag="TestWithFields";
		LoggingNotificationConfig config = getConfig(BODY_TEMPLATE_ADDITIONAL_FIELDS,tag, false);

		EventNotificationContext context = getContext(config);
		when(notificationCallbackService.getBacklogForEvent(context)).thenReturn(messageSummaries);
		loggingAlert.execute(context);

		TestLogger testLogger = TestLoggerFactory.getTestLogger(tag);
		assertThat(testLogger.getLoggingEvents()).extracting("level", "message").contains(
				tuple(INFO, "alert_id: " + context.event().eventDefinitionId() + " | "
						+ "title: " + context.eventDefinition().get().title() + " | "
						+ "description: " + context.eventDefinition().get().description() + " | "
						+ "severity: low | create_time: 2017-09-06T17:00:00.000Z | detect_time: 2017-09-06T17:00:00.000Z | "
						+ "analyzer: Graylog | sensor: sensor | classification: classification | "
						+ "source_ip_address: 192.168.2.10 | "
						+ "source_port: 50000 | "
						+ "target_ip_address: 192.168.2.20 | "
						+ "target_port: 60000 | "
						+ "messages_url: http://localhost:8080"
						+ "/search?rangetype=absolute&from=2017-09-06T17%3A00%3A00.000Z&to=" + formatDate(jobTriggerEndTime.plusMinutes(1))),
				tuple(INFO, "alert_id: " + context.event().eventDefinitionId() + " | "
						+ "title: " + context.eventDefinition().get().title() + " | "
						+ "description: " + context.eventDefinition().get().description() + " | "
						+ "severity: low | create_time: 2017-09-06T17:00:00.000Z | detect_time: 2017-09-06T17:00:00.000Z | "
						+ "analyzer: Graylog | sensor: sensor | classification: classification | "
						+ "source_ip_address: 192.168.2.11 | "
						+ "source_port: 50001 | "
						+ "target_ip_address: 192.168.2.21 | "
						+ "target_port: 60001 | "
						+ "messages_url: http://localhost:8080"
						+ "/search?rangetype=absolute&from=2017-09-06T17%3A00%3A00.000Z&to=" + formatDate(jobTriggerEndTime.plusMinutes(1)))
				);
	}

	@Test
	public void testExecuteWithAdditionalFieldsSingleMessage() throws EventNotificationException {
		Message message = new Message("Test message 1", "source1", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		message.addField("sensor", "sensor");
		message.addField("classification", "classification");
		message.addField("ip_src", "192.168.1.10");
		message.addField("port_src", "50000");
		message.addField("ip_dst", "192.168.1.20");
		message.addField("port_dst", "60000");

		Message message2 = new Message("Test message 2", "source1", new DateTime(2017, 9, 6, 17, 1, DateTimeZone.UTC));
		message2.addField("sensor", "sensor");
		message2.addField("classification", "classification");
		message2.addField("ip_src", "192.168.1.11");
		message2.addField("port_src", "50001");
		message2.addField("ip_dst", "192.168.1.21");
		message2.addField("port_dst", "60001");

		final ImmutableList<MessageSummary> messageSummaries = ImmutableList.of(
				new MessageSummary("graylog_1", message),
				new MessageSummary("graylog_1", message2));

		String tag="TestSingle";
		LoggingNotificationConfig config = getConfig(BODY_TEMPLATE_ADDITIONAL_FIELDS_SINGLE_MESSAGE,tag, true);

		EventNotificationContext context = getContext(config);
		when(notificationCallbackService.getBacklogForEvent(context)).thenReturn(messageSummaries);
		loggingAlert.execute(context);

		TestLogger testLogger = TestLoggerFactory.getTestLogger(tag);
		assertThat(testLogger.getLoggingEvents()).extracting("level", "message").contains(
				tuple(INFO, "alert_id: "+context.event().eventDefinitionId() + " | "
						+ "title: "+context.eventDefinition().get().title() + " | "
						+ "description: "+context.eventDefinition().get().description() + " | "
						+ "severity: low | create_time: 2017-09-06T17:00:00.000Z | detect_time: 2017-09-06T17:00:00.000Z | "
						+ "analyzer: Graylog | "
						+ "messages_url: http://localhost:8080"
						+ "/search?rangetype=absolute&from=2017-09-06T17%3A00%3A00.000Z&to=" + formatDate(dateForTest.plusMinutes(1))
						+ " | sensor: sensor | classification: classification | "
						+ "source_ip_address: 192.168.1.10 | "
						+ "source_port: 50000 | "
						+ "target_ip_address: 192.168.1.20 | "
						+ "target_port: 60000 | "
						+ "sensor: sensor | classification: classification | "
						+ "source_ip_address: 192.168.1.11 | "
						+ "source_port: 50001 | "
						+ "target_ip_address: 192.168.1.21 | "
						+ "target_port: 60001 | "
						));

	}

	private String formatDate(DateTime date) {
		SimpleDateFormat sdf = new SimpleDateFormat("yyy-MM-dd'T'HH'%3A'mm'%3A'ss.SSS'Z'");
		return sdf.format(date.toDate());
	}

	private LoggingNotificationConfig getConfig(String bodyTemplate, String tag, boolean single) {
		return LoggingNotificationConfig.builder()
				.aggregationStream("aggregation_stream")
				.aggregationTime(60)
				.alertTag(tag)
				.fieldAlertId("field_alert_id")
				.limitOverflow(0)
				.logBody(bodyTemplate)
				.overflowTag("overflow_tag")
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
