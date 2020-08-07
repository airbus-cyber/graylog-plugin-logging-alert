package com.airbus_cyber_security.graylog.events.notifications.types;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import com.airbus_cyber_security.graylog.events.config.LoggingAlertConfig;
import org.graylog.events.notifications.EventNotification;
import org.graylog.events.notifications.EventNotificationContext;
import org.graylog.events.notifications.EventNotificationService;
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
    
    private final Searches searches;

	private final String generalConfigSeparator;
    
	public interface Factory extends EventNotification.Factory{
		@Override
		LoggingAlert create();
	}
	
	@Inject
	public LoggingAlert(final ClusterConfigService clusterConfigService, final EventNotificationService notificationCallbackService,
						final ObjectMapper objectMapper, final Searches searches) {
		this.notificationCallbackService = notificationCallbackService;
		this.objectMapper = objectMapper;
		this.searches = searches;

		final LoggingAlertConfig generalConfig = clusterConfigService.getOrDefault(LoggingAlertConfig.class,
				LoggingAlertConfig.createDefault());

		generalConfigSeparator = generalConfig.accessSeparator();
	}
	
	@Override
	public void execute(EventNotificationContext ctx) {
		LOGGER.debug("Start of execute...");
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
			LoggingAlertFields loggingAlertFields = new LoggingAlertFields(LoggingAlertUtils.getAlertID(config, ctx, searches, ""),
					LoggingAlertUtils.getGraylogID(ctx),
					config.severity().getType(),
					date,
					LoggingAlertUtils.getAlertUrl(ctx),
					LoggingAlertUtils.getStreamSearchUrl(ctx, date));
			LoggingAlertUtils.addLogToListMessages(config, listMessagesToLog, model, loggingAlertFields, generalConfigSeparator);
		} else {
			if (config.singleMessage()) {
				LOGGER.debug("Add log to list message for single message...");
				LoggingAlertFields loggingAlertFields = new LoggingAlertFields(LoggingAlertUtils.getAlertID(config, ctx, searches, ""),
						LoggingAlertUtils.getGraylogID(ctx), config.severity().getType(), date,
						LoggingAlertUtils.getAlertUrl(ctx), LoggingAlertUtils.getStreamSearchUrl(ctx, date));
				LoggingAlertUtils.addLogToListMessages(config, listMessagesToLog, model, loggingAlertFields, generalConfigSeparator);
			} else {
				LOGGER.debug("Add log to list message for backlog...");
				Map<String, LoggingAlertFields> listOfloggingAlertField = LoggingAlertUtils.getListOfLoggingAlertField(ctx, backlog, config, model, date, searches);
				for (MessageSummary messageSummary : backlog) {
					model = LoggingAlertUtils.getModel(ctx, messageSummary, objectMapper);
					String valuesAggregationField = LoggingAlertUtils.getValuesAggregationField(messageSummary, config);
					LoggingAlertUtils.addLogToListMessages(config, listMessagesToLog, model, listOfloggingAlertField.get(valuesAggregationField), generalConfigSeparator);
				}
			}
		}

		final Logger LOGGER = LoggerFactory.getLogger(config.alertTag());
		final Logger LOGGER_OVERFLOW = LoggerFactory.getLogger(config.overflowTag());

		Logger localLogger;
		if (config.alertTag() != null && !config.alertTag().isEmpty()) {
			localLogger = LoggerFactory.getLogger(config.alertTag());
		} else {
			localLogger = LOGGER;
		}

		/* Log each messages */
		int iter = 0;
		for (String message : listMessagesToLog) {
			if (config.limitOverflow() <= 0 || iter < config.limitOverflow()) {
				localLogger.info(message);
			} else {
				LOGGER_OVERFLOW.info(message);
			}
			iter++;
		}

		LOGGER.debug("End of execute...");
	}

	
}
