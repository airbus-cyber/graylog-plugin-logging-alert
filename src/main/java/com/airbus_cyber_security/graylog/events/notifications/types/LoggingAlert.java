package com.airbus_cyber_security.graylog.events.notifications.types;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import com.airbus_cyber_security.graylog.events.config.LoggingAlertConfig;
import org.graylog.events.notifications.EventNotification;
import org.graylog.events.notifications.EventNotificationContext;
import org.graylog.events.notifications.EventNotificationService;
import org.graylog.events.search.MoreSearch;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.joda.time.DateTime;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import com.google.inject.Inject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This is the plugin. Your class should implement one of the existing plugin
 * interfaces. (i.e. AlarmCallback, MessageInput, MessageOutput)
 * UPDATE Graylog 3.2 : the class should implement EventNotification
 */
public class LoggingAlert implements EventNotification {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(LoggingAlert.class);

	private final EventNotificationService notificationCallbackService;
    
    private final ObjectMapper objectMapper;
    
    private final MoreSearch moreSearch;

	private final ClusterConfigService clusterConfigService;
    
	public interface Factory extends EventNotification.Factory{
		@Override
		LoggingAlert create();
	}
	
	@Inject
	public LoggingAlert(final ClusterConfigService clusterConfigService, final EventNotificationService notificationCallbackService,
						final ObjectMapper objectMapper, final MoreSearch moreSearch) {
		this.notificationCallbackService = notificationCallbackService;
		this.objectMapper = objectMapper;
		this.moreSearch = moreSearch;
		this.clusterConfigService = clusterConfigService;
	}

	@Override
	public void execute(EventNotificationContext ctx) {
		LOGGER.debug("Start of execute...");
		final LoggingAlertConfig generalConfig = clusterConfigService.getOrDefault(LoggingAlertConfig.class, LoggingAlertConfig.createDefault());
		final LoggingNotificationConfig config = (LoggingNotificationConfig) ctx.notificationConfig();
		final ImmutableList<MessageSummary> backlog = notificationCallbackService.getBacklogForEvent(ctx);

		DateTime date = ctx.event().eventTimestamp();

		for (MessageSummary messageSummary : backlog) {
			if (messageSummary.getTimestamp().isBefore(date))
				date = messageSummary.getTimestamp();
		}

		Set<String> listMessagesToLog = new LinkedHashSet<>();
		Map<String, Object> model = LoggingAlertUtils.getModel(ctx, backlog, objectMapper);

		if (backlog.isEmpty()) {
			LOGGER.debug("Add log to list message for empty backlog...");
			LoggingAlertFields loggingAlertFields = new LoggingAlertFields(
					LoggingAlertUtils.getAlertID(config, generalConfig.accessAggregationStream(), ctx, moreSearch, ""),
					config.severity().getType(),
					date,
					LoggingAlertUtils.getStreamSearchUrl(ctx, date));
			LoggingAlertUtils.addLogToListMessages(config, listMessagesToLog, model, loggingAlertFields, generalConfig.accessSeparator());
		} else {
			if (config.singleMessage()) {
				LOGGER.debug("Add log to list message for single message...");
				LoggingAlertFields loggingAlertFields = new LoggingAlertFields(
						LoggingAlertUtils.getAlertID(config, generalConfig.accessAggregationStream(), ctx, moreSearch,""),
						config.severity().getType(), date,
						LoggingAlertUtils.getStreamSearchUrl(ctx, date));
				LoggingAlertUtils.addLogToListMessages(config, listMessagesToLog, model, loggingAlertFields, generalConfig.accessSeparator());
			} else {
				LOGGER.debug("Add log to list message for backlog...");
				Map<String, LoggingAlertFields> listOfloggingAlertField = LoggingAlertUtils.
						getListOfLoggingAlertField(ctx, backlog, config, generalConfig.accessAggregationStream(), date, moreSearch);
				for (MessageSummary messageSummary : backlog) {
					model = LoggingAlertUtils.getModel(ctx, messageSummary, objectMapper);
					String valuesAggregationField = LoggingAlertUtils.getValuesAggregationField(messageSummary, config);
					LoggingAlertUtils.addLogToListMessages(config, listMessagesToLog, model,
							listOfloggingAlertField.get(valuesAggregationField), generalConfig.accessSeparator());
				}
			}
		}

		final Logger LOGGER = LoggerFactory.getLogger(config.alertTag());
		final Logger LOGGER_OVERFLOW = LoggerFactory.getLogger(generalConfig.accessOverflowTag());

		Logger localLogger;
		if (config.alertTag() != null && !config.alertTag().isEmpty()) {
			localLogger = LoggerFactory.getLogger(config.alertTag());
		} else {
			localLogger = LOGGER;
		}

		/* Log each messages */
		int iter = 0;
		for (String message : listMessagesToLog) {
			if (generalConfig.accessLimitOverflow() <= 0 || iter < generalConfig.accessLimitOverflow()) {
				localLogger.info(message);
			} else {
				LOGGER_OVERFLOW.info(message);
			}
			iter++;
		}

		LOGGER.debug("End of execute...");
	}

	
}
