
package com.airbus_cyber_security.graylog;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.Collections;
import org.graylog2.alerts.AbstractAlertCondition;
import org.graylog2.alerts.Alert;
import org.graylog2.alerts.AlertService;
import org.graylog2.alerts.types.DummyAlertCondition;
import org.graylog2.indexer.IndexSetRegistry;
import org.graylog2.indexer.indices.Indices;
import org.graylog2.indexer.results.ResultMessage;
import org.graylog2.indexer.results.SearchResult;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.indexer.searches.Sorting;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.alarms.AlertCondition;
import org.graylog2.plugin.alarms.callbacks.AlarmCallbackConfigurationException;
import org.graylog2.plugin.alarms.callbacks.AlarmCallbackException;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;
import org.graylog2.plugin.streams.Stream;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.airbus_cyber_security.graylog.events.notifications.types.LoggingAlert;
import com.airbus_cyber_security.graylog.events.config.LoggingAlertConfig;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Maps;

import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import static org.mockito.Mockito.mock;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.groups.Tuple.tuple;
import static uk.org.lidalia.slf4jext.Level.INFO;

import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;

@Ignore
@PrepareForTest({ LoggingAlert.class })
@RunWith(PowerMockRunner.class)
public class LoggingAlertTest {

	private static final String SEPARATOR_TEMPLATE = "\n";
	private static final String BODY_TEMPLATE = 
			"alert_id: ${logging_alert.id}"  + SEPARATOR_TEMPLATE +
			"alert_title: ${alertCondition.title}" + SEPARATOR_TEMPLATE +
			"alert_description: ${check_result.resultDescription}" + SEPARATOR_TEMPLATE +
			"severity: ${logging_alert.severity}" + SEPARATOR_TEMPLATE + 
			"create_time: ${check_result.triggeredAt}" + SEPARATOR_TEMPLATE + 
			"detect_time: ${logging_alert.detect_time}" + SEPARATOR_TEMPLATE + 
			"analyzer: Graylog" + SEPARATOR_TEMPLATE +
			"analyzer_time: ${message.timestamp}" + SEPARATOR_TEMPLATE +
			"sensor: ${message.fields.sensor}" + SEPARATOR_TEMPLATE +
			"classification: ${message.fields.classification}" + SEPARATOR_TEMPLATE +
			"source_command: ${message.fields.cmd_src}" + SEPARATOR_TEMPLATE +
			"source_file_name: ${message.fields.file_src}" + SEPARATOR_TEMPLATE +
			"source_host_name: ${message.fields.host_src}" + SEPARATOR_TEMPLATE +
			"source_ip_address: ${message.fields.ip_src}" + SEPARATOR_TEMPLATE +
			"source_mac_address: ${message.fields.mac_src}" + SEPARATOR_TEMPLATE +
			"source_port: ${message.fields.port_src}" + SEPARATOR_TEMPLATE +
			"source_process: ${message.fields.process_src}" + SEPARATOR_TEMPLATE +
			"source_service_name: ${message.fields.service_src}" + SEPARATOR_TEMPLATE +
			"source_tool: ${message.fields.tool_src}" + SEPARATOR_TEMPLATE +
			"source_url: ${message.fields.url_src}" + SEPARATOR_TEMPLATE +
			"source_user_name: ${message.fields.user_src}" + SEPARATOR_TEMPLATE +
			"source_user_privileges: ${message.fields.user_role_src}" + SEPARATOR_TEMPLATE +
			"source_user_unique_identifier: ${message.fields.uid_src}" + SEPARATOR_TEMPLATE +
			"target_command: ${message.fields.cmd_dst}" + SEPARATOR_TEMPLATE +
			"target_file_name: ${message.fields.file_dst}" + SEPARATOR_TEMPLATE +
			"target_host_name: ${message.fields.host_dst}" + SEPARATOR_TEMPLATE +
			"target_ip_address: ${message.fields.ip_dst}" + SEPARATOR_TEMPLATE +
			"target_mac_address: ${message.fields.mac_dst}" + SEPARATOR_TEMPLATE +
			"target_port: ${message.fields.port_dst}" + SEPARATOR_TEMPLATE +
			"target_process: ${message.fields.process_dst}" + SEPARATOR_TEMPLATE +
			"target_service_name: ${message.fields.service_dst}" + SEPARATOR_TEMPLATE +
			"target_tool: ${message.fields.tool_dst}" + SEPARATOR_TEMPLATE +
			"target_url: ${message.fields.url_dst}" + SEPARATOR_TEMPLATE +
			"target_user_name: ${message.fields.user_dst}" + SEPARATOR_TEMPLATE +
			"target_user_privileges: ${message.fields.user_role_dst}" + SEPARATOR_TEMPLATE +
			"target_user_unique_identifier: ${message.fields.uid_dst}" + SEPARATOR_TEMPLATE +
			"file_name: ${message.fields.filename}" + SEPARATOR_TEMPLATE +
			"file_hash: ${message.fields.filehash}" + SEPARATOR_TEMPLATE +
			"file_size: ${message.fields.filesize}" + SEPARATOR_TEMPLATE +
			"file_type: ${message.fields.filetype}" + SEPARATOR_TEMPLATE +
			"messages_url: http://localhost:8080${logging_alert.messages_url}";
	
	private static final String BODY_TEMPLATE_MSG_URL = 
			"alert_id: ${logging_alert.id}"  + SEPARATOR_TEMPLATE +
			"alert_title: ${alertCondition.title}" + SEPARATOR_TEMPLATE +
			"create_time: ${check_result.triggeredAt}" + SEPARATOR_TEMPLATE + 
			"detect_time: ${logging_alert.detect_time}" + SEPARATOR_TEMPLATE + 
			"messages_url: http://localhost:8080${logging_alert.messages_url}";

	private static final TestLogger TEST_LOGGER = TestLoggerFactory.getTestLogger("LoggingAlert");
	private static final TestLogger TEST_LOGGER_OVERFLOW = TestLoggerFactory.getTestLogger("LoggingOverflow");

	private static final String CONDITION_ID = "condition-id";
	private static final String CONDITION_TITLE = "Alert Condition Title";
	private static final String USER = "user";

	private AlertService alertService;

	@Rule
	public ExpectedException expectedException = ExpectedException.none();

	@Rule
	public final MockitoRule mockitoRule = MockitoJUnit.rule();

	private LoggingAlert loggingAlert;
	private Searches searches;
	private LoggingAlertConfig configGeneral;

	@Before
	public void setUp() throws Exception {
		alertService = mock(AlertService.class);
		searches = mock(Searches.class);
		configGeneral = mock(LoggingAlertConfig.class);
	}

	private Map<String, Object> getConfigMap(String severity, String body, 
			List<String> aggregationField, int aggregationTime, int limitOverflow, String alertTag, boolean singleNotification) {
		Map<String, Object> parameters = Maps.newHashMap();
		parameters.put("severity", severity);
		parameters.put("content", body);
		parameters.put("split_fields", aggregationField);
		parameters.put("aggregation_time", aggregationTime);
		parameters.put("limit_overflow", limitOverflow);
		parameters.put("alert_tag", alertTag);
		parameters.put("single_notification", singleNotification);
		return parameters;
	}

	private void initializeConfiguration(Map<String, Object> configMap) {
		final Configuration configuration = new Configuration(configMap);

		final ClusterConfigService clusterConfigService= mock(ClusterConfigService.class);
		final Indices indices = mock(Indices.class);
		final IndexSetRegistry indexSetRegistry = mock(IndexSetRegistry.class);
	}

	private void initializeSimpleConfiguration() throws AlarmCallbackConfigurationException {
		initializeConfiguration(getConfigMap("info", BODY_TEMPLATE, Collections.emptyList(), 0, 0, null, false));
	}

	@Test
	public void checkConfigurationSucceedsWithValidConfiguration() throws Exception {
		initializeSimpleConfiguration();
	}

	@Test
	public void callWithNoAdditionalField() throws AlarmCallbackConfigurationException {
		initializeSimpleConfiguration();

		Stream stream = mock(Stream.class);

		final AlertCondition alertCondition = new DummyAlertCondition(
				stream,
				CONDITION_ID,
				new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC),
				USER,
				ImmutableMap.of(),
				CONDITION_TITLE
				);

		final List<MessageSummary> messageSummaries = ImmutableList.of(
				new MessageSummary("graylog_1", new Message("Test message 1", "source1", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC))),
				new MessageSummary("graylog_2", new Message("Test message 2", "source2", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC)))
				);
		final AlertCondition.CheckResult checkResult = new AbstractAlertCondition.CheckResult(
				true,
				alertCondition,
				"Result Description",
				new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC),
				messageSummaries
				);

		UUID uuid = UUID.randomUUID();
		mockStatic(UUID.class);
		when(UUID.randomUUID()).thenReturn(uuid);
		when(stream.getId()).thenReturn("001");


		assertThat(TEST_LOGGER.getLoggingEvents()).extracting("level", "message").contains(
				tuple(INFO, "alert_id: "+uuid.toString()+" | alert_title: Alert Condition Title | alert_description: Result Description | "
						+ "severity: info | create_time: 2017-09-06T17:00:00.000Z | detect_time: 2017-09-06T17:00:00.000Z | "
						+ "analyzer: Graylog | analyzer_time: 2017-09-06T17:00:00.000Z | sensor:  | classification:  | "
						+ "source_command:  | source_file_name:  | source_host_name:  | source_ip_address:  | source_mac_address:  | "
						+ "source_port:  | source_process:  | source_service_name:  | source_tool:  | source_url:  | source_user_name:  | "
						+ "source_user_privileges:  | source_user_unique_identifier:  | target_command:  | target_file_name:  | "
						+ "target_host_name:  | target_ip_address:  | target_mac_address:  | target_port:  | target_process:  | "
						+ "target_service_name:  | target_tool:  | target_url:  | target_user_name:  | target_user_privileges:  | "
						+ "target_user_unique_identifier:  | file_name:  | file_hash:  | file_size:  | file_type:  | "
						+ "alert_url: http://localhost:8080 | messages_url: http://localhost:8080"
						+ "/search?rangetype=absolute&from=2017-09-06T16%3A59%3A00.000Z&to=2017-09-06T17%3A01%3A00.000Z&q=streams%3A001"));
	}

	@Test
	public void callWithAdditionalField() throws AlarmCallbackConfigurationException {
		initializeSimpleConfiguration();

		Stream stream = mock(Stream.class);

		final AlertCondition alertCondition = new DummyAlertCondition(
				stream,
				CONDITION_ID,
				new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC),
				USER,
				ImmutableMap.of(),
				CONDITION_TITLE
				);

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

		final List<MessageSummary> messageSummaries = ImmutableList.of(
				new MessageSummary("graylog_1", message));

		final AlertCondition.CheckResult checkResult = new AbstractAlertCondition.CheckResult(
				true,
				alertCondition,
				"Result Description",
				new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC),
				messageSummaries
				);

		UUID uuid = UUID.randomUUID();
		mockStatic(UUID.class);
		when(UUID.randomUUID()).thenReturn(uuid);
		when(stream.getId()).thenReturn("001");

		assertThat(TEST_LOGGER.getLoggingEvents()).extracting("level", "message").contains(
				tuple(INFO, "alert_id: "+uuid.toString()+" | alert_title: Alert Condition Title | alert_description: Result Description | "
						+ "severity: info | create_time: 2017-09-06T17:00:00.000Z | detect_time: 2017-09-06T17:00:00.000Z | "
						+ "analyzer: Graylog | analyzer_time: 2017-09-06T17:00:00.000Z | sensor: sensor | classification: classification | "
						+ "source_command: cmd_src | source_file_name: file_src | source_host_name: host_src | source_ip_address: ip_src | "
						+ "source_mac_address: mac_src | source_port: port_src | source_process: process_src | source_service_name: service_src | "
						+ "source_tool: tool_src | source_url: url_src | source_user_name: user_src | source_user_privileges: user_role_src | "
						+ "source_user_unique_identifier: uid_src | target_command: cmd_dst | target_file_name: file_dst | "
						+ "target_host_name: host_dst | target_ip_address: ip_dst | target_mac_address: mac_dst | target_port: port_dst | "
						+ "target_process: process_dst | target_service_name: service_dst | target_tool: tool_dst | target_url: url_dst | "
						+ "target_user_name: user_dst | target_user_privileges: user_role_dst | target_user_unique_identifier: uid_dst | "
						+ "file_name: filename | file_hash: filehash | file_size: filesize | file_type: filetype | "
						+ "messages_url: http://localhost:8080"
						+ "/search?rangetype=absolute&from=2017-09-06T16%3A59%3A00.000Z&to=2017-09-06T17%3A01%3A00.000Z&q=streams%3A001"));


	}

	@Test
	public void testAggregationWith1Field() throws AlarmCallbackConfigurationException {
		List<String> listAggegationFields = Collections.singletonList(USER);
		initializeConfiguration(getConfigMap("info", "alert_id: ${logging_alert.id}"  + SEPARATOR_TEMPLATE +
				"user: ${message.fields.user}"+SEPARATOR_TEMPLATE+"ip_src: ${message.fields.ip_src}", listAggegationFields, 0, 0,null, false));

		Stream stream = mock(Stream.class);

		final AlertCondition alertCondition = new DummyAlertCondition(
				stream,
				CONDITION_ID,
				new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC),
				USER,
				ImmutableMap.of(),
				CONDITION_TITLE
				);

		Message message1 = new Message("Test message 1", "source1", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		message1.addField(USER, "admin");
		message1.addField("ip_src", "127.0.0.1");
		Message message2 = new Message("Test message 2", "source2", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		message2.addField(USER, "root");
		message2.addField("ip_src", "127.0.0.1");
		Message message3 = new Message("Test message 3", "source3", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		message3.addField(USER, "admin");
		message3.addField("ip_src", "127.0.0.2");

		final List<MessageSummary> messageSummaries = ImmutableList.of(
				new MessageSummary("graylog_1", message1),
				new MessageSummary("graylog_2", message2),
				new MessageSummary("graylog_3", message3)

				);
		final AlertCondition.CheckResult checkResult = new AbstractAlertCondition.CheckResult(
				true,
				alertCondition,
				"Result Description",
				new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC),
				messageSummaries
				);

		UUID randomUuid = UUID.randomUUID();
		String valuesAggregationField="admin";
		String alertID1 = randomUuid + "-" + valuesAggregationField.hashCode();
		String valuesAggregationField2="root";
		String alertID2 = randomUuid + "-" + valuesAggregationField2.hashCode();
		mockStatic(UUID.class);
		when(UUID.randomUUID()).thenReturn(randomUuid);

		assertThat(TEST_LOGGER.getLoggingEvents()).extracting("level", "message").containsExactlyInAnyOrder(
				tuple(INFO, "alert_id: "+alertID1+" | user: admin | ip_src: 127.0.0.1"),
				tuple(INFO, "alert_id: "+alertID2+" | user: root | ip_src: 127.0.0.1"),
				tuple(INFO, "alert_id: "+alertID1+" | user: admin | ip_src: 127.0.0.2"));

	}

	@Test
	public void testDeduped()  throws AlarmCallbackException, AlarmCallbackConfigurationException {
		List<String> listAggegationFields = Collections.singletonList(USER);
		initializeConfiguration(getConfigMap("info", "alert_id: ${logging_alert.id}"  + SEPARATOR_TEMPLATE +
				"user: ${message.fields.user}", listAggegationFields, 0, 0,null, false));

		Stream stream = mock(Stream.class);

		final AlertCondition alertCondition = new DummyAlertCondition(
				stream,
				CONDITION_ID,
				new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC),
				USER,
				ImmutableMap.of(),
				CONDITION_TITLE
				);

		Message message1 = new Message("Test message 1", "source1", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		message1.addField(USER, "admin");
		Message message2 = new Message("Test message 2", "source2", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		message2.addField(USER, "root");
		Message message3 = new Message("Test message 3", "source3", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		message3.addField(USER, "admin");

		final List<MessageSummary> messageSummaries = ImmutableList.of(
				new MessageSummary("graylog_1", message1),
				new MessageSummary("graylog_2", message2),
				new MessageSummary("graylog_3", message3)

				);
		final AlertCondition.CheckResult checkResult = new AbstractAlertCondition.CheckResult(
				true,
				alertCondition,
				"Result Description",
				new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC),
				messageSummaries
				);

		UUID randomUuid = UUID.randomUUID();
		String valuesAggregationField="admin";
		String alertID1 = randomUuid +"-" + valuesAggregationField.hashCode();
		String valuesAggregationField2="root";
		String alertID2 = randomUuid +"-" + valuesAggregationField2.hashCode();
		mockStatic(UUID.class);
		when(UUID.randomUUID()).thenReturn(randomUuid);

		assertThat(TEST_LOGGER.getLoggingEvents()).extracting("level", "message").containsExactlyInAnyOrder(
				tuple(INFO, "alert_id: "+alertID1+" | user: admin"),
				tuple(INFO, "alert_id: "+alertID2+" | user: root"));

	}

	@Test
	public void testAggregationWithMultipleField() throws AlarmCallbackConfigurationException {
		List<String> listAggegationFields = Arrays.asList(USER,"ip_src");
		initializeConfiguration(getConfigMap("info", "alert_id: ${logging_alert.id}"  + SEPARATOR_TEMPLATE +
				"user: ${message.fields.user}" +SEPARATOR_TEMPLATE+"ip_src: ${message.fields.ip_src}", listAggegationFields, 0, 0,null, false));

		Stream stream = mock(Stream.class);

		final AlertCondition alertCondition = new DummyAlertCondition(
				stream,
				CONDITION_ID,
				new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC),
				USER,
				ImmutableMap.of(),
				CONDITION_TITLE
				);

		Message message1 = new Message("Test message 1", "source1", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		message1.addField(USER, "admin");
		message1.addField("ip_src", "127.0.0.1");
		Message message2 = new Message("Test message 2", "source2", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		message2.addField(USER, "root");
		message2.addField("ip_src", "127.0.0.1");
		Message message3 = new Message("Test message 3", "source3", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		message3.addField(USER, "admin");
		message3.addField("ip_src", "127.0.0.2");

		final List<MessageSummary> messageSummaries = ImmutableList.of(
				new MessageSummary("graylog_1", message1),
				new MessageSummary("graylog_2", message2),
				new MessageSummary("graylog_3", message3)

				);
		final AlertCondition.CheckResult checkResult = new AbstractAlertCondition.CheckResult(
				true,
				alertCondition,
				"Result Description",
				new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC),
				messageSummaries
				);

		UUID randomUuid = UUID.randomUUID();
		String valuesAggregationField="admin127.0.0.1";
		String alertID1 = randomUuid +"-" + valuesAggregationField.hashCode();
		String valuesAggregationField2="root127.0.0.1";
		String alertID2 = randomUuid +"-" + valuesAggregationField2.hashCode();
		String valuesAggregationField3="admin127.0.0.2";
		String alertID3 = randomUuid +"-" + valuesAggregationField3.hashCode();
		mockStatic(UUID.class);
		when(UUID.randomUUID()).thenReturn(randomUuid);

		assertThat(TEST_LOGGER.getLoggingEvents()).extracting("level", "message").containsExactlyInAnyOrder(
				tuple(INFO, "alert_id: "+alertID1+" | user: admin | ip_src: 127.0.0.1"),
				tuple(INFO, "alert_id: "+alertID2+" | user: root | ip_src: 127.0.0.1"),
				tuple(INFO, "alert_id: "+alertID3+" | user: admin | ip_src: 127.0.0.2"));

	}

	@Test
	public void testWithAggregationTime() throws AlarmCallbackConfigurationException {
		List<String> listAggegationFields = Collections.singletonList(USER);
		initializeConfiguration(getConfigMap("info", "alert_id: ${logging_alert.id}"  + SEPARATOR_TEMPLATE +
				"user: ${message.fields.user}"+SEPARATOR_TEMPLATE+"ip_src: ${message.fields.ip_src}", listAggegationFields, 15, 0,null, false));

		Stream stream = mock(Stream.class);

		final AlertCondition alertCondition = new DummyAlertCondition(
				stream,
				CONDITION_ID,
				new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC),
				"",
				ImmutableMap.of(),
				CONDITION_TITLE
				);

		Message message1 = new Message("Test message 1", "source1", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		message1.addField(USER, "admin");
		message1.addField("ip_src", "127.0.0.1");
		Message message2 = new Message("Test message 2", "source2", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		message2.addField(USER, "root");
		message2.addField("ip_src", "127.0.0.1");
		Message message3 = new Message("Test message 3", "source3", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		message3.addField(USER, "admin");
		message3.addField("ip_src", "127.0.0.2");

		final List<MessageSummary> messageSummaries = ImmutableList.of(
				new MessageSummary("graylog_1", message1),
				new MessageSummary("graylog_2", message2),
				new MessageSummary("graylog_3", message3)

				);
		final AlertCondition.CheckResult checkResult = new AbstractAlertCondition.CheckResult(
				true,
				alertCondition,
				"Result Description",
				new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC),
				messageSummaries
				);

		when(stream.getId()).thenReturn("001");
		List<Alert> listAlert = new ArrayList<>();
		Alert alert = mock(Alert.class);
		when(alert.getId()).thenReturn("002");
		listAlert.add(alert);
		when(alertService.loadRecentOfStream(stream.getId(), new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC).minusMinutes(15), 300)).thenReturn(listAlert);

		SearchResult backlogResult =  mock(SearchResult.class);
		Message message = new Message("alert_id: alertId","test",new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		message.addField("alert_id", "alertID");
		ResultMessage resultMessage = mock(ResultMessage.class);
		List<ResultMessage> listResultMessage = new ArrayList<>();
		listResultMessage.add(resultMessage);
		when(resultMessage.getMessage()).thenReturn(message);
		when(backlogResult.getResults()).thenReturn(listResultMessage);

		when(searches.search(anyString(), anyString(), any(TimeRange.class), eq(10), eq(0), any(Sorting.class))).thenReturn(backlogResult);

		assertThat(TEST_LOGGER.getLoggingEvents()).extracting("level", "message").containsExactlyInAnyOrder(
				tuple(INFO, "alert_id: "+"alertID"+" | user: admin | ip_src: 127.0.0.1"),
				tuple(INFO, "alert_id: "+"alertID"+" | user: root | ip_src: 127.0.0.1"),
				tuple(INFO, "alert_id: "+"alertID"+" | user: admin | ip_src: 127.0.0.2"));

	}

	@Test
	public void testWithFieldAlerId() throws AlarmCallbackConfigurationException {
		List<String> listAggegationFields = Collections.singletonList("user");
		initializeConfiguration(getConfigMap("info", "alert_id: ${logging_alert.id}"  + SEPARATOR_TEMPLATE +
				"user: ${message.fields.user}"+SEPARATOR_TEMPLATE+"ip_src: ${message.fields.ip_src}",listAggegationFields, 0, 0,null, false));

		Stream stream = mock(Stream.class);

		final AlertCondition alertCondition = new DummyAlertCondition(
				stream,
				"condition-id",
				new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC),
				"user",
				ImmutableMap.of(),
				"Alert Condition Title"
				);

		Message message1 = new Message("Test message 1", "source1", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		message1.addField("user", "admin");
		message1.addField("ip_src", "127.0.0.1");
		Message message2 = new Message("Test message 2", "source2", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		message2.addField("user", "root");
		message2.addField("ip_src", "127.0.0.1");
		Message message3 = new Message("Test message 3", "source3", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		message3.addField("user", "admin");
		message3.addField("ip_src", "127.0.0.2");
		message3.addField("alert_id", "1");

		final List<MessageSummary> messageSummaries = ImmutableList.of(
				new MessageSummary("graylog_1", message1),
				new MessageSummary("graylog_2", message2),
				new MessageSummary("graylog_3", message3)

				);
		final AlertCondition.CheckResult checkResult = new AbstractAlertCondition.CheckResult(
				true,
				alertCondition,
				"Result Description",
				new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC),
				messageSummaries
				);	

		UUID randomUuid = UUID.randomUUID();
		String valuesAggregationField2="root";
		String alertID2 = randomUuid +"-" + valuesAggregationField2.hashCode();
		mockStatic(UUID.class);
		when(UUID.randomUUID()).thenReturn(randomUuid);


		assertThat(TEST_LOGGER.getLoggingEvents()).extracting("level", "message").containsExactlyInAnyOrder(
				tuple(INFO, "alert_id: "+1+" | user: admin | ip_src: 127.0.0.1"),
				tuple(INFO, "alert_id: "+alertID2+" | user: root | ip_src: 127.0.0.1"),
				tuple(INFO, "alert_id: "+1+" | user: admin | ip_src: 127.0.0.2"));
	}

	@Test
	public void callWithUrlAlertisInterval() throws AlarmCallbackConfigurationException {
		initializeSimpleConfiguration();

		Stream stream = mock(Stream.class);

		final AlertCondition alertCondition = new DummyAlertCondition(
				stream,
				CONDITION_ID,
				new DateTime(2017, 9, 6, 00, 0, DateTimeZone.UTC),
				USER,
				ImmutableMap.of(),
				CONDITION_TITLE
				);

		final List<MessageSummary> messageSummaries = ImmutableList.of(
				new MessageSummary("graylog_1", new Message("Test message 1", "source1", new DateTime(2018, 4, 19, 00, 0, DateTimeZone.UTC))),
				new MessageSummary("graylog_2", new Message("Test message 2", "source2", new DateTime(2018, 4, 19, 00, 0, DateTimeZone.UTC)))
				);
		final AlertCondition.CheckResult checkResult = new AbstractAlertCondition.CheckResult(
				true,
				alertCondition,
				"Result Description",
				new DateTime(2018, 4, 19, 00, 0, DateTimeZone.UTC),
				messageSummaries
				);

		UUID uuid = UUID.randomUUID();
		mockStatic(UUID.class);
		when(UUID.randomUUID()).thenReturn(uuid);

		Alert alert = mock(Alert.class);
		when(alert.getId()).thenReturn("002");
		when(alert.isInterval()).thenReturn(true);
		when(alert.getTriggeredAt()).thenReturn(new DateTime(2018, 04, 19, 00, 01, 27, DateTimeZone.UTC));
		when(alert.getResolvedAt()).thenReturn(new DateTime(2018, 04, 19, 00, 02, 27, DateTimeZone.UTC));
		Optional<Alert> optAlert = Optional.of(alert);

		when(stream.getId()).thenReturn("001");
		when(alertService.getLastTriggeredAlert(anyString(), anyString())).thenReturn(optAlert);


		assertThat(TEST_LOGGER.getLoggingEvents()).extracting("level", "message").contains(
				tuple(INFO, "alert_id: 002 | alert_title: Alert Condition Title | alert_description: Result Description | "
						+ "severity: info | create_time: 2018-04-19T00:00:00.000Z | detect_time: 2018-04-19T00:00:00.000Z | "
						+ "analyzer: Graylog | analyzer_time: 2018-04-19T00:00:00.000Z | sensor:  | classification:  | "
						+ "source_command:  | source_file_name:  | source_host_name:  | source_ip_address:  | source_mac_address:  | "
						+ "source_port:  | source_process:  | source_service_name:  | source_tool:  | source_url:  | source_user_name:  | "
						+ "source_user_privileges:  | source_user_unique_identifier:  | target_command:  | target_file_name:  | "
						+ "target_host_name:  | target_ip_address:  | target_mac_address:  | target_port:  | target_process:  | "
						+ "target_service_name:  | target_tool:  | target_url:  | target_user_name:  | target_user_privileges:  | "
						+ "target_user_unique_identifier:  | file_name:  | file_hash:  | file_size:  | file_type:  | "
						+ "messages_url: http://localhost:8080"
						+ "/search?rangetype=absolute&from="
						+ "2018-04-19T00%3A00%3A00.000Z&to=2018-04-19T00%3A03%3A27.000Z&q=streams%3A001"));
	}

	@Test
	public void callWithUrlAlertisNotInterval() throws AlarmCallbackConfigurationException {
		initializeSimpleConfiguration();

		Stream stream = mock(Stream.class);

		final AlertCondition alertCondition = new DummyAlertCondition(
				stream,
				CONDITION_ID,
				new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC),
				USER,
				ImmutableMap.of(),
				CONDITION_TITLE
				);

		final List<MessageSummary> messageSummaries = ImmutableList.of(
				new MessageSummary("graylog_1", new Message("Test message 1", "source1", new DateTime(2018, 4, 19, 14, 0, DateTimeZone.UTC))),
				new MessageSummary("graylog_2", new Message("Test message 2", "source2", new DateTime(2018, 4, 19, 14, 0, DateTimeZone.UTC)))
				);
		final AlertCondition.CheckResult checkResult = new AbstractAlertCondition.CheckResult(
				true,
				alertCondition,
				"Result Description",
				new DateTime(2018, 4, 19, 14, 0, DateTimeZone.UTC),
				messageSummaries
				);

		UUID uuid = UUID.randomUUID();
		mockStatic(UUID.class);
		when(UUID.randomUUID()).thenReturn(uuid);

		Alert alert = mock(Alert.class);
		when(alert.getId()).thenReturn("002");
		when(alert.isInterval()).thenReturn(false);
		when(alert.getTriggeredAt()).thenReturn(new DateTime(2018, 04, 19, 14, 01, 27, DateTimeZone.UTC));
		when(alert.getResolvedAt()).thenReturn(new DateTime(2018, 04, 19, 14, 02, 27, DateTimeZone.UTC));
		Optional<Alert> optAlert = Optional.of(alert);

		when(stream.getId()).thenReturn("001");
		when(alertService.getLastTriggeredAlert(anyString(), anyString())).thenReturn(optAlert);


		assertThat(TEST_LOGGER.getLoggingEvents()).extracting("level", "message").contains(
				tuple(INFO, "alert_id: 002 | alert_title: Alert Condition Title | alert_description: Result Description | "
						+ "severity: info | create_time: 2018-04-19T14:00:00.000Z | detect_time: 2018-04-19T14:00:00.000Z | "
						+ "analyzer: Graylog | analyzer_time: 2018-04-19T14:00:00.000Z | sensor:  | classification:  | "
						+ "source_command:  | source_file_name:  | source_host_name:  | source_ip_address:  | source_mac_address:  | "
						+ "source_port:  | source_process:  | source_service_name:  | source_tool:  | source_url:  | source_user_name:  | "
						+ "source_user_privileges:  | source_user_unique_identifier:  | target_command:  | target_file_name:  | "
						+ "target_host_name:  | target_ip_address:  | target_mac_address:  | target_port:  | target_process:  | "
						+ "target_service_name:  | target_tool:  | target_url:  | target_user_name:  | target_user_privileges:  | "
						+ "target_user_unique_identifier:  | file_name:  | file_hash:  | file_size:  | file_type:  | "
						+ "messages_url: http://localhost:8080"
						+ "/search?rangetype=absolute&from="
						+ "2018-04-19T14%3A00%3A00.000Z&to=2018-04-19T14%3A02%3A27.000Z&q=streams%3A001"));
	}

	@Test
	public void testLimitOverflow() throws  AlarmCallbackConfigurationException {

		List<String> listAggegationFields = Collections.singletonList(USER);
		initializeConfiguration(getConfigMap("info", "alert_id: ${logging_alert.id}"  + SEPARATOR_TEMPLATE +
				"user: ${message.fields.user}"+SEPARATOR_TEMPLATE+"ip_src: ${message.fields.ip_src}", listAggegationFields, 0, 2,null, false));

		Stream stream = mock(Stream.class);

		final AlertCondition alertCondition = new DummyAlertCondition(
				stream,
				CONDITION_ID,
				new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC),
				USER,
				ImmutableMap.of(),
				CONDITION_TITLE
				);

		Message message1 = new Message("Test message 1", "source1", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		message1.addField(USER, "admin");
		message1.addField("ip_src", "127.0.0.1");
		Message message2 = new Message("Test message 2", "source2", new DateTime(2017, 9, 6, 17, 1, DateTimeZone.UTC));
		message2.addField(USER, "admin");
		message2.addField("ip_src", "127.0.0.2");
		Message message3 = new Message("Test message 3", "source3", new DateTime(2017, 9, 6, 17, 2, DateTimeZone.UTC));
		message3.addField(USER, "admin");
		message3.addField("ip_src", "127.0.0.3");

		final List<MessageSummary> messageSummaries = ImmutableList.of(
				new MessageSummary("graylog_1", message1),
				new MessageSummary("graylog_2", message2),
				new MessageSummary("graylog_3", message3)
				);

		final AlertCondition.CheckResult checkResult = new AbstractAlertCondition.CheckResult(
				true,
				alertCondition,
				"Result Description",
				new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC),
				messageSummaries
				);

		UUID randomUuid = UUID.randomUUID();
		String valuesAggregationField="admin";
		String alertID1 = randomUuid + "-" + valuesAggregationField.hashCode();
		mockStatic(UUID.class);
		when(UUID.randomUUID()).thenReturn(randomUuid);


		assertThat(TEST_LOGGER.getLoggingEvents()).extracting("level", "message").containsExactlyInAnyOrder(
				tuple(INFO, "alert_id: "+alertID1+" | user: admin | ip_src: 127.0.0.1"),
				tuple(INFO, "alert_id: "+alertID1+" | user: admin | ip_src: 127.0.0.2"));

		assertThat(TEST_LOGGER_OVERFLOW.getLoggingEvents()).extracting("level", "message").containsExactlyInAnyOrder(
				tuple(INFO, "alert_id: "+alertID1+" | user: admin | ip_src: 127.0.0.3"));


	}

	@Test
	public void callWithSplitFieldTestMessageUrl() throws AlarmCallbackConfigurationException {
		List<String> listAggegationFields = Collections.singletonList(USER);
		initializeConfiguration(getConfigMap("info", BODY_TEMPLATE, listAggegationFields, 0, 0,null, false));

		Stream stream = mock(Stream.class);

		final AlertCondition alertCondition = new DummyAlertCondition(
				stream,
				CONDITION_ID,
				new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC),
				USER,
				ImmutableMap.of(),
				CONDITION_TITLE
				);

		Message message1 = new Message("Test message 1", "source1", new DateTime(2018, 4, 19, 14, 0, DateTimeZone.UTC));
		message1.addField(USER, "admin");
		message1.addField("ip_src", "127.0.0.1");
		Message message2 = new Message("Test message 2", "source2", new DateTime(2018, 4, 19, 14, 1, DateTimeZone.UTC));
		message2.addField(USER, "admin");
		message2.addField("ip_src", "127.0.0.2");
		Message message3 = new Message("Test message 3", "source3", new DateTime(2018, 4, 19, 14, 2, DateTimeZone.UTC));
		message3.addField(USER, "user1");
		message3.addField("ip_src", "127.0.0.3");

		final List<MessageSummary> messageSummaries = ImmutableList.of(
				new MessageSummary("graylog_1", message1),
				new MessageSummary("graylog_2", message2),
				new MessageSummary("graylog_3", message3)
				);

		final AlertCondition.CheckResult checkResult = new AbstractAlertCondition.CheckResult(
				true,
				alertCondition,
				"Result Description",
				new DateTime(2018, 4, 19, 14, 0, DateTimeZone.UTC),
				messageSummaries
				);

		UUID uuid = UUID.randomUUID();
		mockStatic(UUID.class);
		when(UUID.randomUUID()).thenReturn(uuid);

		Alert alert = mock(Alert.class);
		when(alert.getId()).thenReturn("002");
		when(alert.isInterval()).thenReturn(true);
		when(alert.getTriggeredAt()).thenReturn(new DateTime(2018, 04, 19, 14, 01, 27, DateTimeZone.UTC));
		when(alert.getResolvedAt()).thenReturn(new DateTime(2018, 04, 19, 14, 02, 27, DateTimeZone.UTC));
		Optional<Alert> optAlert = Optional.of(alert);

		when(stream.getId()).thenReturn("001");
		when(alertService.getLastTriggeredAlert(anyString(), anyString())).thenReturn(optAlert);


		assertThat(TEST_LOGGER.getLoggingEvents()).extracting("level", "message").containsExactlyInAnyOrder(
				tuple(INFO, "alert_id: 002-92668751 | alert_title: Alert Condition Title | alert_description: Result Description "
						+ "| severity: info | create_time: 2018-04-19T14:00:00.000Z | detect_time: 2018-04-19T14:00:00.000Z "
						+ "| analyzer: Graylog | analyzer_time: 2018-04-19T14:00:00.000Z | sensor:  | classification:  "
						+ "| source_command:  | source_file_name:  | source_host_name:  | source_ip_address: 127.0.0.1 "
						+ "| source_mac_address:  | source_port:  | source_process:  | source_service_name:  | source_tool:  "
						+ "| source_url:  | source_user_name:  | source_user_privileges:  | source_user_unique_identifier:  "
						+ "| target_command:  | target_file_name:  | target_host_name:  | target_ip_address:  "
						+ "| target_mac_address:  | target_port:  | target_process:  | target_service_name:  | target_tool:  "
						+ "| target_url:  | target_user_name:  | target_user_privileges:  | target_user_unique_identifier:  "
						+ "| file_name:  | file_hash:  | file_size:  | file_type:  "
						+ "| messages_url: http://localhost:8080/search?rangetype=absolute"
						+ "&from=2018-04-19T14%3A00%3A00.000Z&to=2018-04-19T14%3A03%3A27.000Z&q=streams%3A001+AND+user%3A\"admin\""),
				tuple(INFO, "alert_id: 002-92668751 | alert_title: Alert Condition Title | alert_description: Result Description "
						+ "| severity: info | create_time: 2018-04-19T14:00:00.000Z | detect_time: 2018-04-19T14:00:00.000Z "
						+ "| analyzer: Graylog | analyzer_time: 2018-04-19T14:01:00.000Z | sensor:  | classification:  "
						+ "| source_command:  | source_file_name:  | source_host_name:  | source_ip_address: 127.0.0.2 "
						+ "| source_mac_address:  | source_port:  | source_process:  | source_service_name:  | source_tool:  "
						+ "| source_url:  | source_user_name:  | source_user_privileges:  | source_user_unique_identifier:  "
						+ "| target_command:  | target_file_name:  | target_host_name:  | target_ip_address:  "
						+ "| target_mac_address:  | target_port:  | target_process:  | target_service_name:  | target_tool:  "
						+ "| target_url:  | target_user_name:  | target_user_privileges:  | target_user_unique_identifier:  "
						+ "| file_name:  | file_hash:  | file_size:  | file_type:  "
						+ "| messages_url: http://localhost:8080/search?rangetype=absolute"
						+ "&from=2018-04-19T14%3A00%3A00.000Z&to=2018-04-19T14%3A03%3A27.000Z&q=streams%3A001+AND+user%3A\"admin\""),
				tuple(INFO, "alert_id: 002-111578566 | alert_title: Alert Condition Title | alert_description: Result Description "
						+ "| severity: info | create_time: 2018-04-19T14:00:00.000Z | detect_time: 2018-04-19T14:00:00.000Z "
						+ "| analyzer: Graylog | analyzer_time: 2018-04-19T14:02:00.000Z | sensor:  | classification:  "
						+ "| source_command:  | source_file_name:  | source_host_name:  | source_ip_address: 127.0.0.3 "
						+ "| source_mac_address:  | source_port:  | source_process:  | source_service_name:  | source_tool:  "
						+ "| source_url:  | source_user_name:  | source_user_privileges:  | source_user_unique_identifier:  "
						+ "| target_command:  | target_file_name:  | target_host_name:  | target_ip_address:  "
						+ "| target_mac_address:  | target_port:  | target_process:  | target_service_name:  | target_tool:  "
						+ "| target_url:  | target_user_name:  | target_user_privileges:  | target_user_unique_identifier:  "
						+ "| file_name:  | file_hash:  | file_size:  | file_type:  "
						+ "| messages_url: http://localhost:8080/search?rangetype=absolute"
						+ "&from=2018-04-19T14%3A00%3A00.000Z&to=2018-04-19T14%3A03%3A27.000Z&q=streams%3A001+AND+user%3A\"user1\""));


	}
		
	@Test
	public void testMsgURLWithPreviousMsgsURL() throws AlarmCallbackConfigurationException {
		List<String> listAggegationFields = Collections.singletonList(USER);
		initializeConfiguration(getConfigMap("info", BODY_TEMPLATE_MSG_URL, listAggegationFields, 15, 0,null, false));

		Stream stream = mock(Stream.class);

		final AlertCondition alertCondition = new DummyAlertCondition(
				stream,
				CONDITION_ID,
				new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC),
				USER,
				ImmutableMap.of(),
				CONDITION_TITLE
				);

		Message message1 = new Message("Test message 1", "source1", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		message1.addField(USER, "admin");
		message1.addField("ip_src", "127.0.0.1");
		Message message2 = new Message("Test message 2", "source2", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		message2.addField(USER, "root");
		message2.addField("ip_src", "127.0.0.1");
		Message message3 = new Message("Test message 3", "source3", new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		message3.addField(USER, "admin");
		message3.addField("ip_src", "127.0.0.2");

		final List<MessageSummary> messageSummaries = ImmutableList.of(
				new MessageSummary("graylog_1", message1),
				new MessageSummary("graylog_2", message2),
				new MessageSummary("graylog_3", message3)

				);
		final AlertCondition.CheckResult checkResult = new AbstractAlertCondition.CheckResult(
				true,
				alertCondition,
				"Result Description",
				new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC),
				messageSummaries
				);

		when(stream.getId()).thenReturn("001");
		List<Alert> listAlert = new ArrayList<>();
		Alert alert = mock(Alert.class);
		when(alert.getId()).thenReturn("002");
		when(alert.getTriggeredAt()).thenReturn(new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		when(alert.getResolvedAt()).thenReturn(new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		Map <String, Object> conditionParameters = Maps.newHashMap();
		conditionParameters.put("additional_stream", "005");
		when(alert.getConditionParameters()).thenReturn(conditionParameters);
		Optional<Alert> optAlert = Optional.of(alert);
		when(alertService.getLastTriggeredAlert(anyString(), anyString())).thenReturn(optAlert);
		listAlert.add(alert);
		when(alertService.loadRecentOfStream(stream.getId(), new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC).minusMinutes(15), 300)).thenReturn(listAlert);

		String dateFromPreviousMsg = "2017-09-06T16%3A00%3A00.000Z";
		String streamIdPreviousMsg = "012345678901234567890123";
		
		SearchResult backlogResult =  mock(SearchResult.class);
		Message message = new Message("alert_id: alertId","test",new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC));
		message.addField("alert_id", "alertID");
		message.addField("messages_url", "http://localhost:8080/search?rangetype=absolute&from="
										+ dateFromPreviousMsg
										+ "&to=2017-09-06T17%3A01%3A00.000Z&q=streams%3A"
										+streamIdPreviousMsg +"AND+user%3A\"admin\"");
		ResultMessage resultMessage = mock(ResultMessage.class);
		List<ResultMessage> listResultMessage = new ArrayList<>();
		listResultMessage.add(resultMessage);
		when(resultMessage.getMessage()).thenReturn(message);
		when(backlogResult.getResults()).thenReturn(listResultMessage);

		when(searches.search(anyString(), anyString(), any(TimeRange.class), eq(10), eq(0), any(Sorting.class))).thenReturn(backlogResult);


		assertThat(TEST_LOGGER.getLoggingEvents()).extracting("level", "message").containsExactlyInAnyOrder(
				tuple(INFO, "alert_id: "+"alertID"+" | alert_title: Alert Condition Title | "
						+ "create_time: 2017-09-06T17:00:00.000Z | "
						+ "detect_time: 2017-09-06T17:00:00.000Z | "
						+ "messages_url: http://localhost:8080/search?rangetype=absolute&"
						+ "from=" + dateFromPreviousMsg
						+ "&to=2017-09-06T17%3A01%3A00.000Z&q="
						+ "(+streams%3A001+OR+streams%3A" + streamIdPreviousMsg
						+ "+)+AND+user%3A\"admin\""),
				tuple(INFO, "alert_id: "+"alertID"+" | alert_title: Alert Condition Title | "
						+ "create_time: 2017-09-06T17:00:00.000Z | "
						+ "detect_time: 2017-09-06T17:00:00.000Z | "
						+ "messages_url: http://localhost:8080/search?rangetype=absolute&"
						+ "from=" + dateFromPreviousMsg
						+ "&to=2017-09-06T17%3A01%3A00.000Z&q="
						+ "(+streams%3A001+OR+streams%3A" + streamIdPreviousMsg
						+ "+)+AND+user%3A\"root\""));

	}
	
	@Test
	public void callWithSplitFieldNotPresent() throws AlarmCallbackConfigurationException {
		List<String> listAggegationFields = Collections.singletonList(USER);
		initializeConfiguration(getConfigMap("info", BODY_TEMPLATE, listAggegationFields, 0, 0,null, false));

		Stream stream = mock(Stream.class);

		final AlertCondition alertCondition = new DummyAlertCondition(
				stream,
				CONDITION_ID,
				new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC),
				USER,
				ImmutableMap.of(),
				CONDITION_TITLE
				);

		Message message1 = new Message("Test message 1", "source1", new DateTime(2018, 4, 19, 14, 0, DateTimeZone.UTC));
		message1.addField(USER, "admin");
		message1.addField("ip_src", "127.0.0.1");
		Message message2 = new Message("Test message 2", "source2", new DateTime(2018, 4, 19, 14, 1, DateTimeZone.UTC));
		message2.addField("ip_src", "127.0.0.2");
		Message message3 = new Message("Test message 3", "source3", new DateTime(2018, 4, 19, 14, 2, DateTimeZone.UTC));
		message3.addField(USER, "user1");
		message3.addField("ip_src", "127.0.0.3");

		final List<MessageSummary> messageSummaries = ImmutableList.of(
				new MessageSummary("graylog_1", message1),
				new MessageSummary("graylog_2", message2),
				new MessageSummary("graylog_3", message3)
				);

		final AlertCondition.CheckResult checkResult = new AbstractAlertCondition.CheckResult(
				true,
				alertCondition,
				"Result Description",
				new DateTime(2018, 4, 19, 14, 0, DateTimeZone.UTC),
				messageSummaries
				);

		UUID uuid = UUID.randomUUID();
		mockStatic(UUID.class);
		when(UUID.randomUUID()).thenReturn(uuid);

		Alert alert = mock(Alert.class);
		when(alert.getId()).thenReturn("002");
		when(alert.isInterval()).thenReturn(true);
		when(alert.getTriggeredAt()).thenReturn(new DateTime(2018, 04, 19, 14, 01, 27, DateTimeZone.UTC));
		when(alert.getResolvedAt()).thenReturn(new DateTime(2018, 04, 19, 14, 02, 27, DateTimeZone.UTC));
		Optional<Alert> optAlert = Optional.of(alert);

		when(stream.getId()).thenReturn("001");
		when(alertService.getLastTriggeredAlert(anyString(), anyString())).thenReturn(optAlert);


		assertThat(TEST_LOGGER.getLoggingEvents()).extracting("level", "message").containsExactlyInAnyOrder(
				tuple(INFO, "alert_id: 002-92668751 | alert_title: Alert Condition Title | alert_description: Result Description "
						+ "| severity: info | create_time: 2018-04-19T14:00:00.000Z | detect_time: 2018-04-19T14:00:00.000Z "
						+ "| analyzer: Graylog | analyzer_time: 2018-04-19T14:00:00.000Z | sensor:  | classification:  "
						+ "| source_command:  | source_file_name:  | source_host_name:  | source_ip_address: 127.0.0.1 "
						+ "| source_mac_address:  | source_port:  | source_process:  | source_service_name:  | source_tool:  "
						+ "| source_url:  | source_user_name:  | source_user_privileges:  | source_user_unique_identifier:  "
						+ "| target_command:  | target_file_name:  | target_host_name:  | target_ip_address:  "
						+ "| target_mac_address:  | target_port:  | target_process:  | target_service_name:  | target_tool:  "
						+ "| target_url:  | target_user_name:  | target_user_privileges:  | target_user_unique_identifier:  "
						+ "| file_name:  | file_hash:  | file_size:  | file_type:  "
						+ "| messages_url: http://localhost:8080/search?rangetype=absolute"
						+ "&from=2018-04-19T14%3A00%3A00.000Z&to=2018-04-19T14%3A03%3A27.000Z&q=streams%3A001+AND+user%3A\"admin\""),
				tuple(INFO, "alert_id: 002-3392903 | alert_title: Alert Condition Title | alert_description: Result Description "
						+ "| severity: info | create_time: 2018-04-19T14:00:00.000Z | detect_time: 2018-04-19T14:00:00.000Z "
						+ "| analyzer: Graylog | analyzer_time: 2018-04-19T14:01:00.000Z | sensor:  | classification:  "
						+ "| source_command:  | source_file_name:  | source_host_name:  | source_ip_address: 127.0.0.2 "
						+ "| source_mac_address:  | source_port:  | source_process:  | source_service_name:  | source_tool:  "
						+ "| source_url:  | source_user_name:  | source_user_privileges:  | source_user_unique_identifier:  "
						+ "| target_command:  | target_file_name:  | target_host_name:  | target_ip_address:  "
						+ "| target_mac_address:  | target_port:  | target_process:  | target_service_name:  | target_tool:  "
						+ "| target_url:  | target_user_name:  | target_user_privileges:  | target_user_unique_identifier:  "
						+ "| file_name:  | file_hash:  | file_size:  | file_type:  "
						+ "| messages_url: http://localhost:8080/search?rangetype=absolute"
						+ "&from=2018-04-19T14%3A00%3A00.000Z&to=2018-04-19T14%3A03%3A27.000Z&q=streams%3A001"),
				tuple(INFO, "alert_id: 002-111578566 | alert_title: Alert Condition Title | alert_description: Result Description "
						+ "| severity: info | create_time: 2018-04-19T14:00:00.000Z | detect_time: 2018-04-19T14:00:00.000Z "
						+ "| analyzer: Graylog | analyzer_time: 2018-04-19T14:02:00.000Z | sensor:  | classification:  "
						+ "| source_command:  | source_file_name:  | source_host_name:  | source_ip_address: 127.0.0.3 "
						+ "| source_mac_address:  | source_port:  | source_process:  | source_service_name:  | source_tool:  "
						+ "| source_url:  | source_user_name:  | source_user_privileges:  | source_user_unique_identifier:  "
						+ "| target_command:  | target_file_name:  | target_host_name:  | target_ip_address:  "
						+ "| target_mac_address:  | target_port:  | target_process:  | target_service_name:  | target_tool:  "
						+ "| target_url:  | target_user_name:  | target_user_privileges:  | target_user_unique_identifier:  "
						+ "| file_name:  | file_hash:  | file_size:  | file_type:  "
						+ "| messages_url: http://localhost:8080/search?rangetype=absolute"
						+ "&from=2018-04-19T14%3A00%3A00.000Z&to=2018-04-19T14%3A03%3A27.000Z&q=streams%3A001+AND+user%3A\"user1\""));


	}

	@Test
	public void callWithListMsgEmpty() throws AlarmCallbackConfigurationException {
		initializeSimpleConfiguration();

		Stream stream = mock(Stream.class);

		final AlertCondition alertCondition = new DummyAlertCondition(
				stream,
				CONDITION_ID,
				new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC),
				USER,
				ImmutableMap.of(),
				CONDITION_TITLE
		);

		final AlertCondition.CheckResult checkResult = new AbstractAlertCondition.CheckResult(
				true,
				alertCondition,
				"Result Description",
				new DateTime(2018, 4, 19, 14, 0, DateTimeZone.UTC),
				Collections.emptyList()
		);

		UUID uuid = UUID.randomUUID();
		mockStatic(UUID.class);
		when(UUID.randomUUID()).thenReturn(uuid);

		Alert alert = mock(Alert.class);
		when(alert.getId()).thenReturn("002");
		when(alert.isInterval()).thenReturn(false);
		when(alert.getTriggeredAt()).thenReturn(new DateTime(2018, 04, 19, 14, 01, 27, DateTimeZone.UTC));
		when(alert.getResolvedAt()).thenReturn(new DateTime(2018, 04, 19, 14, 02, 27, DateTimeZone.UTC));
		Optional<Alert> optAlert = Optional.of(alert);

		when(stream.getId()).thenReturn("001");
		when(alertService.getLastTriggeredAlert(anyString(), anyString())).thenReturn(optAlert);


		assertThat(TEST_LOGGER.getLoggingEvents()).extracting("level", "message").contains(
				tuple(INFO, "alert_id: 002 | alert_title: Alert Condition Title | alert_description: Result Description | "
						+ "severity: info | create_time: 2018-04-19T14:00:00.000Z | detect_time: 2018-04-19T14:00:00.000Z | "
						+ "analyzer: Graylog | analyzer_time: 2018-04-19T14:00:00.000Z | sensor:  | classification:  | "
						+ "source_command:  | source_file_name:  | source_host_name:  | source_ip_address:  | source_mac_address:  | "
						+ "source_port:  | source_process:  | source_service_name:  | source_tool:  | source_url:  | source_user_name:  | "
						+ "source_user_privileges:  | source_user_unique_identifier:  | target_command:  | target_file_name:  | "
						+ "target_host_name:  | target_ip_address:  | target_mac_address:  | target_port:  | target_process:  | "
						+ "target_service_name:  | target_tool:  | target_url:  | target_user_name:  | target_user_privileges:  | "
						+ "target_user_unique_identifier:  | file_name:  | file_hash:  | file_size:  | file_type:  | "
						+ "messages_url: http://localhost:8080"
						+ "/search?rangetype=absolute&from="
						+ "2018-04-19T13%3A59%3A00.000Z&to=2018-04-19T14%3A01%3A00.000Z&q=streams%3A001"));
	}

	@Test
	public void callWithSpecificTagAndSingleNotification() throws AlarmCallbackConfigurationException {
		String template = "type: alert\n" +
							"id: ${logging_alert.id}\n" +
							"severity: ${logging_alert.severity}\n" +
							"app: graylog\n" +
							"subject: ${alertCondition.title}\n" +
							"body: ${check_result.resultDescription}\n" +
							"ip_srcs: [${foreach messages message}${message.fields.ip_src},${end}]";

		initializeConfiguration(getConfigMap("info", template, Collections.emptyList(), 0, 0,"SpecificTag", true));

		Stream stream = mock(Stream.class);

		final AlertCondition alertCondition = new DummyAlertCondition(
				stream,
				CONDITION_ID,
				new DateTime(2017, 9, 6, 17, 0, DateTimeZone.UTC),
				USER,
				ImmutableMap.of(),
				CONDITION_TITLE
		);

		Message message1 = new Message("Test message 1", "source1", new DateTime(2018, 4, 19, 14, 0, DateTimeZone.UTC));
		message1.addField(USER, "admin");
		message1.addField("ip_src", "127.0.0.1");
		Message message2 = new Message("Test message 2", "source2", new DateTime(2018, 4, 19, 14, 1, DateTimeZone.UTC));
		message2.addField("ip_src", "127.0.0.2");
		Message message3 = new Message("Test message 3", "source3", new DateTime(2018, 4, 19, 14, 2, DateTimeZone.UTC));
		message3.addField(USER, "user1");
		message3.addField("ip_src", "127.0.0.3");

		final List<MessageSummary> messageSummaries = ImmutableList.of(
				new MessageSummary("graylog_1", message1),
				new MessageSummary("graylog_2", message2),
				new MessageSummary("graylog_3", message3)
		);

		final AlertCondition.CheckResult checkResult = new AbstractAlertCondition.CheckResult(
				true,
				alertCondition,
				"Result Description",
				new DateTime(2018, 4, 19, 14, 0, DateTimeZone.UTC),
				messageSummaries
		);

		UUID uuid = UUID.randomUUID();
		mockStatic(UUID.class);
		when(UUID.randomUUID()).thenReturn(uuid);

		Alert alert = mock(Alert.class);
		when(alert.getId()).thenReturn("002");
		when(alert.isInterval()).thenReturn(true);
		when(alert.getTriggeredAt()).thenReturn(new DateTime(2018, 04, 19, 14, 01, 27, DateTimeZone.UTC));
		when(alert.getResolvedAt()).thenReturn(new DateTime(2018, 04, 19, 14, 02, 27, DateTimeZone.UTC));
		Optional<Alert> optAlert = Optional.of(alert);

		when(stream.getId()).thenReturn("001");
		when(alertService.getLastTriggeredAlert(anyString(), anyString())).thenReturn(optAlert);


		final TestLogger testLogger = TestLoggerFactory.getTestLogger("SpecificTag");
		assertThat(testLogger.getLoggingEvents()).extracting("level", "message").containsExactlyInAnyOrder(
				tuple(INFO, "type: alert | id: 002 | severity: info | app: graylog | subject: Alert Condition Title " +
						"| body: Result Description | ip_srcs: [127.0.0.1,127.0.0.2,127.0.0.3,]"));
		
	}
	
	@After
	public void clearLoggers() {
		TestLoggerFactory.clear();
	}
	
}
