package com.airbus_cyber_security.graylog;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.graylog.events.notifications.EventNotification;
import org.graylog.events.notifications.EventNotificationContext;
import org.graylog.events.notifications.EventNotificationException;
import org.graylog.events.notifications.EventNotificationModelData;
import org.graylog.events.notifications.EventNotificationService;
import org.graylog.events.processor.EventDefinitionDto;
import org.graylog.scheduler.JobTriggerDto;
import org.graylog2.indexer.IndexSetRegistry;
import org.graylog2.indexer.indices.Indices;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.jackson.TypeReferences;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.configuration.Configuration;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.airbus_cyber_security.graylog.config.LoggingAlertConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import com.google.inject.Inject;

/**
 * This is the plugin. Your class should implement one of the existing plugin
 * interfaces. (i.e. AlarmCallback, MessageInput, MessageOutput)
 * UPDATE Graylog 3.2 : the class should implement EventNotification
 */
public class LoggingAlert implements EventNotification{
	
	private static final String FIELD_SEVERITY = "severity";
	private static final String FIELD_SINGLE_MESSAGE = "single_notification";
//	
	private final Indices indices;
	private final IndexSetRegistry indexSetRegistry;
	
    private static final String UNKNOWN = "<unknown>";
    
    private final EventNotificationService notificationCallbackService;
    
    private final ObjectMapper objectMapper;
    
    private final Searches searches;
    
	public interface Factory extends EventNotification.Factory{
		@Override
		LoggingAlert create();
	}
	
	@Inject
	public LoggingAlert(final EventNotificationService notificationCallbackService, final ObjectMapper objectMapper, final Searches searches, 
			final Indices indices, final IndexSetRegistry indexSetRegistry) {
		this.notificationCallbackService = notificationCallbackService;
		this.objectMapper = objectMapper;
		this.searches = searches;
		this.indices = indices;
		this.indexSetRegistry = indexSetRegistry;
	}
	
	@Override
	public void execute(EventNotificationContext ctx) throws EventNotificationException {
		final LoggingAlertConfig config = (LoggingAlertConfig) ctx.notificationConfig();
		final ImmutableList<MessageSummary> backlog = notificationCallbackService.getBacklogForEvent(ctx);
		
		DateTime date = ctx.jobTrigger().get().triggeredAt().get();
		
		for (MessageSummary messageSummary : backlog) {
			if(messageSummary.getTimestamp().isBefore(date))
				date = messageSummary.getTimestamp();
		}
		
		Configuration configuration = LoggingAlertUtils.getConfiguration(config, indices, indexSetRegistry);
		Set<String> listMessagesToLog = new LinkedHashSet<>();
		final Map<String, Object> model = getModel(ctx, backlog);
		
		if(backlog.isEmpty()) {
			Message message = new Message(model);
			LoggingAlertFields loggingAlertFields = new LoggingAlertFields(LoggingAlertUtils.getAlertID(config, message, ctx, searches, ""), 
					LoggingAlertUtils.getGraylogID(ctx, message), 
					config.severity().getType(), 
					date, 
					LoggingAlertUtils.getAlertUrl(ctx), 
					LoggingAlertUtils.getStreamSearchUrl(ctx, date));
			addLogToListMessages(config, listMessagesToLog, model, loggingAlertFields);
		} else {
			if(configuration.getBoolean(FIELD_SINGLE_MESSAGE)){
				for (MessageSummary messageSummary : backlog) {
					Message message = messageSummary.getRawMessage();
					LoggingAlertFields loggingAlertFields= new LoggingAlertFields( LoggingAlertUtils.getAlertID(config, message, ctx, searches, ""),
							LoggingAlertUtils.getGraylogID(ctx, message), configuration.getString(FIELD_SEVERITY), date, 
							LoggingAlertUtils.getAlertUrl(ctx), LoggingAlertUtils.getStreamSearchUrl(ctx, date));
//					ArrayList <Message> listMessages = new ArrayList<>();
//					listMessages.add(message);
					addLogToListMessages(config, listMessagesToLog, model, loggingAlertFields);
				}
			}else {
				Map<String, LoggingAlertFields> listOfloggingAlertField = LoggingAlertUtils.getListOfloggingAlertField(ctx, backlog, config, model, date, configuration, searches);
				for (MessageSummary messageSummary : backlog) {
					String valuesAggregationField = LoggingAlertUtils.getValuesAggregationField(messageSummary, configuration);
					addLogToListMessages(config, listMessagesToLog, model, listOfloggingAlertField.get(valuesAggregationField));
				}
			}
		}
		
		
		String messageToLog = LoggingAlertUtils.buildBody(config, model);
		
//		final Logger LOGGER = LoggerFactory.getLogger(config.alertTag());
//		LOGGER.info(messageToLog);
		
	}

	private void addLogToListMessages(final LoggingAlertConfig config, Set<String> listMessagesToLog,
			final Map<String, Object> model, LoggingAlertFields loggingAlertFields) {
		model.put("logging_alert", loggingAlertFields);
		String messageToLog=LoggingAlertUtils.buildBody(config, model);
		listMessagesToLog.add(messageToLog);
	}
	
	private Map<String, Object> getModel(final EventNotificationContext context, final ImmutableList<MessageSummary> backlog) {
		final Optional<EventDefinitionDto> definitionDto = context.eventDefinition();
		final Optional<JobTriggerDto> jobTriggerDto = context.jobTrigger();
		final EventNotificationModelData modelData = EventNotificationModelData.builder()
				.eventDefinitionId(definitionDto.map(EventDefinitionDto::id).orElse(UNKNOWN))
				.eventDefinitionType(definitionDto.map(d -> d.config().type()).orElse(UNKNOWN))
				.eventDefinitionTitle(definitionDto.map(EventDefinitionDto::title).orElse(UNKNOWN))
				.eventDefinitionDescription(definitionDto.map(EventDefinitionDto::description).orElse(UNKNOWN))
				.jobDefinitionId(jobTriggerDto.map(JobTriggerDto::jobDefinitionId).orElse(UNKNOWN))
                .jobTriggerId(jobTriggerDto.map(JobTriggerDto::id).orElse(UNKNOWN))
				.event(context.event())
				.backlog(backlog)
				.build();
		return objectMapper.convertValue(modelData, TypeReferences.MAP_STRING_OBJECT);
	}
	
}
