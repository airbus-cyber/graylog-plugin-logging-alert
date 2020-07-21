package com.airbus_cyber_security.graylog;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import com.airbus_cyber_security.graylog.config.LoggingNotificationConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.graylog.events.notifications.EventNotificationContext;
import org.graylog.events.notifications.EventNotificationModelData;
import org.graylog.events.processor.EventDefinitionDto;
import org.graylog.scheduler.JobTriggerDto;
import org.graylog2.indexer.results.SearchResult;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.indexer.searches.Sorting;
import org.graylog2.jackson.TypeReferences;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.Tools;
import org.graylog2.plugin.indexer.searches.timeranges.AbsoluteRange;
import org.graylog2.plugin.indexer.searches.timeranges.InvalidRangeParametersException;
import org.graylog2.plugin.indexer.searches.timeranges.RelativeRange;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import com.floreysoft.jmte.Engine;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LoggingAlertUtils {

	private static final Logger LOGGER = LoggerFactory.getLogger(LoggingAlertUtils.class);
	
	private static final String MSGS_URL_BEGIN = "/search?rangetype=absolute&from=";
	private static final String MSGS_URL_TO = "&to=";
	private static final String MSGS_URL_STREAM = "&streams=";
	private static final int SIZE_STREAM = 24;

	private static final String SEPARATOR_TEMPLATE = "\n";
	
	private static final String UNKNOWN = "<unknown>";
	
	private static final Engine templateEngine = new Engine();
	
	public static String buildBody(LoggingNotificationConfig config, Map<String, Object> model, String separator) {
		return templateEngine.transform(config.logBody().replace(SEPARATOR_TEMPLATE, separator), model);
	}
	
	public static String getAggregationAlertID(LoggingNotificationConfig config, EventNotificationContext ctx, Searches searches, String sufixID) {
		LOGGER.debug("Start of getAggregationAlertID...");
		try {
			RelativeRange relativeRange = RelativeRange.create(config.aggregationTime() * 60);
			final AbsoluteRange range = AbsoluteRange.create(relativeRange.getFrom(), relativeRange.getTo());

			final String filter = "streams:" + config.aggregationStream();

			if(ctx.eventDefinition().isPresent()) {
				StringBuilder bldStringsearchQuery = new StringBuilder(config.fieldAlertId()+": "+ctx.notificationId()+sufixID);
				bldStringsearchQuery.append(" OR "+config.fieldAlertId()+": "+ctx.notificationId()+sufixID);

		    	final SearchResult backlogResult = searches.search(bldStringsearchQuery.toString(), filter,
						range, 10, 0, new Sorting(Message.FIELD_TIMESTAMP, Sorting.Direction.DESC));

		    	if(backlogResult != null && !backlogResult.getResults().isEmpty()) {
		    		return backlogResult.getResults().get(0).getMessage().getField(config.fieldAlertId()).toString();
		    	}
			}
		} catch (InvalidRangeParametersException e) {
			LOGGER.error("[getAggregationAlertID] - ERROR!", e);
		}
    	return null;
    }
    
	public static String getGraylogID(EventNotificationContext ctx) {
    	if (ctx.eventDefinition().isPresent()) {
    		return ctx.eventDefinition().get().id();
    	}
    	else {
    		return null;
    	}
    }
    
	public static String getNewAlertID(EventNotificationContext ctx) {
    	String graylogID = getGraylogID(ctx);
    	if(graylogID != null) {
			return graylogID;
		}else {
			return UUID.randomUUID().toString();
		}
    }
    
	public static String getAlertID(LoggingNotificationConfig config, EventNotificationContext ctx, Searches searches, String sufixID) {
    	String loggingAlertID = null;
    	    	
		if(config.aggregationTime() > 0 &&
				config.aggregationStream() != null && !config.aggregationStream().isEmpty()) {
			loggingAlertID = getAggregationAlertID(config, ctx, searches, sufixID);
		}
		
		if(loggingAlertID == null || loggingAlertID.isEmpty()) {
			loggingAlertID = getNewAlertID(ctx) + sufixID;
		}
		return loggingAlertID;
    }
    
	public static String getValuesAggregationField(MessageSummary messageSummary, LoggingNotificationConfig config) {
    	StringBuilder valuesAggregationField = new StringBuilder();
    	for (String field : config.splitFields()) {
			valuesAggregationField.append(messageSummary.getField(field));
		}
    	return valuesAggregationField.toString();
    }
    
	public static String getAlertUrl(EventNotificationContext ctx)
    {
    	if (ctx.eventDefinition().isPresent()) {
    		return "/alerts/";//TODO: after demo confirm to which URL to return"/event/"+ctx.eventDefinition().get().id();
    	}
    	return "";
    }
    
	public static String getPreviousMessagesURL(String streamID, DateTime timeBegin, DateTime timeEnd, Searches searches) {
    	final String filter = "streams:" + streamID;	
		final AbsoluteRange range = AbsoluteRange.create(timeBegin, timeEnd);
    	final SearchResult backlogResult = searches.search("*", filter,
				range, 10, 0, new Sorting(Message.FIELD_TIMESTAMP, Sorting.Direction.DESC));

		if(!backlogResult.getResults().isEmpty()) {
			Object fieldMsgUrl = backlogResult.getResults().get(0).getMessage().getField("messages_url");
			if (fieldMsgUrl != null) {
				return fieldMsgUrl.toString();
			}
		}

    	return null;
    }
    
	public static DateTime getTimeFrom(String msgsURL, DateTimeFormatter timeFormatter) {   	
    	int indexBegin = msgsURL.indexOf(MSGS_URL_BEGIN);
    	int indexEnd = msgsURL.indexOf(MSGS_URL_TO);
    	if(indexBegin > 0 && indexEnd > 0) {
    		String date = msgsURL.substring(indexBegin+MSGS_URL_BEGIN.length(), indexEnd);
    		try {
    			return DateTime.parse(date, timeFormatter);
    		}catch(Exception e) {
    			/* Invalid date */
				LOGGER.error("[getTimeFrom] - ERROR!", e);
    		}
    	}
    	
    	return null;
    }
    
	public static String getQuery(String msgsURL) {
    	StringBuilder query = new StringBuilder();
    	int indexBegin = msgsURL.indexOf(MSGS_URL_STREAM);
    	while(indexBegin > 0) {
    		int indexEnd = indexBegin + MSGS_URL_STREAM.length() + SIZE_STREAM;
    		query.append("+OR+" + msgsURL.substring(indexBegin, indexEnd));
    		indexBegin = msgsURL.indexOf(MSGS_URL_STREAM, indexEnd);
    	}
    	
    	return query.toString();
    }

	public static String getStreamSearchUrl(EventNotificationContext ctx, DateTime timeBeginSearch){
		DateTimeFormatter timeFormatter = DateTimeFormat.forPattern("yyy-MM-dd'T'HH'%3A'mm'%3A'ss.SSS'Z'");
		String message_url = MSGS_URL_BEGIN
				+ timeBeginSearch.toString(timeFormatter) + MSGS_URL_TO
				+ ctx.event().eventTimestamp().plusMinutes(1).toString(timeFormatter);
		return ctx.event().sourceStreams().isEmpty() ? message_url : message_url + "&q=" + MSGS_URL_STREAM + getConcatStreams(ctx.event().sourceStreams());
	}

	public static String getMessagesUrl(EventNotificationContext ctx, LoggingNotificationConfig config, Map <String, Object> conditionParameters, MessageSummary messageSummary,
			DateTime timeBeginSearch, Searches searches)
    {
    	DateTimeFormatter timeFormatter = DateTimeFormat.forPattern("yyy-MM-dd'T'HH'%3A'mm'%3A'ss.SSS'Z'");
    	if(ctx.eventDefinition().isPresent()) {

    		DateTime endTime;
    		/* If the alert is interval and resolved */
    		if(ctx.jobTrigger().isPresent() && ctx.jobTrigger().get().endTime().isPresent()) {
    			endTime = ctx.jobTrigger().get().endTime().get().plusMinutes(1);
    		}else {
    			endTime = ctx.jobTrigger().get().triggeredAt().get().plusMinutes(1);
    		}

    		/* when the alert is unresolved and the repeat notification is active */
	    	int timeRange = Tools.getNumber(ctx.jobTrigger().get().createdAt(), 1).intValue();
	    	if(endTime.isBefore(timeBeginSearch.plusMinutes(timeRange))) {
	    		endTime = timeBeginSearch.plusMinutes(timeRange);
	    	}

    		DateTime beginTime = timeBeginSearch;

	    	String search = "";
			String concatStream = getConcatStreams(ctx.event().sourceStreams());
			if (!concatStream.isEmpty()) {
				search = "&q=" + MSGS_URL_STREAM + concatStream;
			}

    		if(conditionParameters.containsKey("additional_stream")) {
    			String additionalStreamID = (String) conditionParameters.get("additional_stream");

    			String previousMsgsURL =  getPreviousMessagesURL(additionalStreamID, beginTime, endTime, searches);
    			if(previousMsgsURL!= null && !previousMsgsURL.isEmpty()) {
    				DateTime timeFromMsgsUrl = getTimeFrom(previousMsgsURL, timeFormatter);
    				if(timeFromMsgsUrl != null && timeFromMsgsUrl.isBefore(beginTime)){
    					beginTime = timeFromMsgsUrl;
    				}
					if (!concatStream.isEmpty()) {
						search = "&q=(+" + MSGS_URL_STREAM + concatStream + getQuery(previousMsgsURL) + "+)";
					}
    			}
    		}

    		StringBuilder searchFields = new StringBuilder();
    		for (String field : config.splitFields()) {
    			String valueAggregationField = (String) messageSummary.getField(field);
    			if(valueAggregationField != null && !valueAggregationField.isEmpty()) {
    				searchFields.append("+AND+" + field + "%3A\"" + valueAggregationField + "\"");
    			}
    		}

    		return MSGS_URL_BEGIN
    		+ beginTime.toString(timeFormatter) + MSGS_URL_TO
    		+ endTime.toString(timeFormatter)
    		+ search
    		+ searchFields.toString();
    	}

		return getStreamSearchUrl(ctx, timeBeginSearch);
    }
    
	public static String getHashFromString(String value) {
    	int hash = value.hashCode();
		if(hash < 0) {
			return "a"+Math.abs(hash);
		}
    	return String.valueOf(hash);
    }
    
	public static Map<String, LoggingAlertFields> getListOfLoggingAlertField(EventNotificationContext ctx, ImmutableList<MessageSummary> backlog, LoggingNotificationConfig config,
							 Map<String, Object> model, DateTime date, Searches searches) {
		String alertUrl = getAlertUrl(ctx);
		Map<String, LoggingAlertFields> listOfLoggingAlertField = Maps.newHashMap();

		for (MessageSummary messageSummary : backlog) {		
			String valuesAggregationField = getValuesAggregationField(messageSummary, config);
			String messagesUrl = getMessagesUrl(ctx, config, model, messageSummary, date, searches);
			String graylogId = getGraylogID(ctx);

			if(messageSummary.hasField(config.fieldAlertId())) {
				listOfLoggingAlertField.put(valuesAggregationField,	new LoggingAlertFields((String) messageSummary.getField(config.fieldAlertId()),
						graylogId, config.severity().getType(), date, alertUrl, messagesUrl));
			}else {
				if(!listOfLoggingAlertField.containsKey(valuesAggregationField)) {
					/* Add hash code if split field */
					String alertID = null;
					Message message = messageSummary.getRawMessage();
					if(valuesAggregationField.equals("")) {
						alertID = getAlertID(config, ctx, searches, "");
					}else {
						alertID = getAlertID(config, ctx, searches, "-"+getHashFromString(valuesAggregationField));
					}
					listOfLoggingAlertField.put(valuesAggregationField,
							 new LoggingAlertFields(alertID, graylogId, config.severity().getType(), date, alertUrl, messagesUrl));
				}	
			}
		}

		return listOfLoggingAlertField;
    }

	public static void addLogToListMessages(final LoggingNotificationConfig config, Set<String> listMessagesToLog,
									  final Map<String, Object> model, LoggingAlertFields loggingAlertFields, String separator) {
		model.put("logging_alert", loggingAlertFields);
		String messageToLog=buildBody(config, model, separator);
		listMessagesToLog.add(messageToLog);
	}

	public static Map<String, Object> getModel(final EventNotificationContext context, final ImmutableList<MessageSummary> backlog,
											   final ObjectMapper objectMapper) {
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

	public static Map<String, Object> getModel(final EventNotificationContext context, final MessageSummary message,
											   final ObjectMapper objectMapper) {
		final Optional<EventDefinitionDto> definitionDto = context.eventDefinition();
		final Optional<JobTriggerDto> jobTriggerDto = context.jobTrigger();
		ImmutableList<MessageSummary> backlog = new ImmutableList.Builder<MessageSummary>().add(message).build();
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

	public static final String getConcatStreams(Set<String> setStreams) {
		String concatStream = "";
		if (!setStreams.isEmpty()) {
			for (String stream : setStreams) {
				concatStream = concatStream.isEmpty() ? concatStream.concat(stream) : concatStream.concat("%2C"+stream);
			}
		}
		return concatStream;
	}
}
