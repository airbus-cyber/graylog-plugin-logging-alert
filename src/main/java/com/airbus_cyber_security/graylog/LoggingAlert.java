package com.airbus_cyber_security.graylog;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import com.airbus_cyber_security.graylog.config.LoggingNotificationConfig;
import org.graylog.events.notifications.EventNotification;
import org.graylog.events.notifications.EventNotificationContext;
import org.graylog.events.notifications.EventNotificationException;
import org.graylog.events.notifications.EventNotificationService;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.plugin.MessageSummary;
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
public class LoggingAlert implements EventNotification{
	
	private static final Logger LOGGER = LoggerFactory.getLogger(LoggingAlert.class);

	private final EventNotificationService notificationCallbackService;
    
    private final ObjectMapper objectMapper;
    
    private final Searches searches;
    
	public interface Factory extends EventNotification.Factory{
		@Override
		LoggingAlert create();
	}
	
	@Inject
	public LoggingAlert(final EventNotificationService notificationCallbackService, final ObjectMapper objectMapper, final Searches searches) {
		this.notificationCallbackService = notificationCallbackService;
		this.objectMapper = objectMapper;
		this.searches = searches;
	}
	
	@Override
	public void execute(EventNotificationContext ctx) throws EventNotificationException {
		LOGGER.info("Start of execute...");
		try {
			final LoggingNotificationConfig config = (LoggingNotificationConfig) ctx.notificationConfig();
			final ImmutableList<MessageSummary> backlog = notificationCallbackService.getBacklogForEvent(ctx);
			LOGGER.info("GOT config and backlog");
			LOGGER.info("Config : "+ config.toString());

			LOGGER.info("context : " + ctx.toString());
			DateTime date = ctx.event().eventTimestamp();
			LOGGER.info("Got date : " + date.toString());
			for (MessageSummary messageSummary : backlog) {
				LOGGER.info("Message : " + messageSummary.toString());
				if (messageSummary.getTimestamp().isBefore(date))
					date = messageSummary.getTimestamp();
			}
			LOGGER.info("Got date : " + date.toString());
			Set<String> listMessagesToLog = new LinkedHashSet<>();
			final Map<String, Object> model = LoggingAlertUtils.getModel(ctx, backlog, objectMapper);

			if (backlog.isEmpty()) {
				LOGGER.info("Add log to list message for empty backlog...");
				LoggingAlertFields loggingAlertFields = new LoggingAlertFields(LoggingAlertUtils.getAlertID(config, ctx, searches, ""),
						LoggingAlertUtils.getGraylogID(ctx),
						config.severity().getType(),
						date,
						LoggingAlertUtils.getAlertUrl(ctx),
						LoggingAlertUtils.getStreamSearchUrl(ctx, date));
				LoggingAlertUtils.addLogToListMessages(config, listMessagesToLog, model, loggingAlertFields);
			} else {
				if (config.singleMessage()) {
					LOGGER.info("Add log to list message for single message...");
					for (MessageSummary messageSummary : backlog) {
						LoggingAlertFields loggingAlertFields = new LoggingAlertFields(LoggingAlertUtils.getAlertID(config, ctx, searches, ""),
								LoggingAlertUtils.getGraylogID(ctx), config.severity().getType(), date,
								LoggingAlertUtils.getAlertUrl(ctx), LoggingAlertUtils.getStreamSearchUrl(ctx, date));
						LoggingAlertUtils.addLogToListMessages(config, listMessagesToLog, model, loggingAlertFields);
					}
				} else {
					LOGGER.info("Add log to list message for backlog...");
					Map<String, LoggingAlertFields> listOfloggingAlertField = LoggingAlertUtils.getListOfLoggingAlertField(ctx, backlog, config, model, date, searches);
					for (MessageSummary messageSummary : backlog) {
						String valuesAggregationField = LoggingAlertUtils.getValuesAggregationField(messageSummary, config);
						LoggingAlertUtils.addLogToListMessages(config, listMessagesToLog, model, listOfloggingAlertField.get(valuesAggregationField));
					}
				}
			}

			final Logger LOGGER = LoggerFactory.getLogger(config.alertTag());
			final Logger LOGGER_OVERFLOW = LoggerFactory.getLogger(config.overflowTag());

			Logger localLogger;
			if(config.alertTag() != null && !config.alertTag().isEmpty()){
				localLogger = LoggerFactory.getLogger(config.alertTag());
			}else{
				localLogger = LOGGER;
			}

			/* Log each messages */
			int iter = 0;
			for (String message : listMessagesToLog) {
				if(config.limitOverflow() <= 0 || iter < config.limitOverflow()) {
					localLogger.info(message);
				} else {
					LOGGER_OVERFLOW.info(message);
				}
				iter++;
			}

		} catch (Exception e) {
			throw new EventNotificationException();
		}
	}

	
}
