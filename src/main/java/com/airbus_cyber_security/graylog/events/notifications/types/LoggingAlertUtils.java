package com.airbus_cyber_security.graylog.events.notifications.types;

import java.util.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.graylog.events.notifications.EventNotificationContext;
import org.graylog.events.notifications.EventNotificationModelData;
import org.graylog.events.processor.EventDefinitionDto;
import org.graylog.events.search.MoreSearch;
import org.graylog.scheduler.JobTriggerDto;
import org.graylog2.indexer.results.ResultMessage;
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

import static org.graylog2.plugin.streams.Stream.DEFAULT_EVENTS_STREAM_ID;

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

	public static String getAggregationAlertID(LoggingNotificationConfig config, EventNotificationContext ctx, MoreSearch moreSearch, String sufixID) {
		LOGGER.debug("Start of getAggregationAlertID...");
		try {
			RelativeRange relativeRange = RelativeRange.create(config.aggregationTime() * 60);
			final AbsoluteRange range = AbsoluteRange.create(relativeRange.getFrom(), relativeRange.getTo());

			String filter = "streams:" + DEFAULT_EVENTS_STREAM_ID;
			String query = "event_definition_id: " + ctx.eventDefinition().get().id();

			final SearchResult result = moreSearch.search(query, filter,
					range, 50, 0, new Sorting(Message.FIELD_TIMESTAMP, Sorting.Direction.DESC));

			if (result != null && !result.getResults().isEmpty()) {
				LOGGER.debug(result.getResults().size()+" Events found");

				Iterator<ResultMessage> itMessages = result.getResults().iterator();
				StringBuilder bldStringsearchQuery = new StringBuilder(config.fieldAlertId()+": "+ itMessages.next().getMessage().getId()+sufixID);
				while (itMessages.hasNext()) {
					bldStringsearchQuery.append(" OR "+config.fieldAlertId()+": "+itMessages.next().getMessage().getId()+sufixID);
				}

				LOGGER.debug("Alert Query: "+bldStringsearchQuery);

				String filter2 = "streams:" + config.aggregationStream();

				LOGGER.debug("Alert filter: "+filter2);

				final SearchResult result2 = moreSearch.search(bldStringsearchQuery.toString(), filter2,
						range, 50, 0, new Sorting(Message.FIELD_TIMESTAMP, Sorting.Direction.DESC));

				if (result2 != null && !result2.getResults().isEmpty()) {
					LOGGER.debug(result2.getResults().size()+" Alert found");
					return result2.getResults().get(0).getMessage().getField(config.fieldAlertId()).toString();
				}
			}

		} catch (InvalidRangeParametersException e) {
			LOGGER.debug("[getAggregationAlertID] - ERROR!", e);
		}
    	return null;
    }

	public static String getAlertID(LoggingNotificationConfig config, EventNotificationContext ctx, MoreSearch moreSearch, String sufixID) {

    	String loggingAlertID = null;
    	    	
		if(config.aggregationTime() > 0 &&
				config.aggregationStream() != null && !config.aggregationStream().isEmpty()) {
			loggingAlertID = getAggregationAlertID(config, ctx, moreSearch, sufixID);
		}
		
		if(loggingAlertID == null || loggingAlertID.isEmpty()) {
			loggingAlertID = ctx.event().id() + sufixID;
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
		return ctx.event().sourceStreams().isEmpty() ? message_url : message_url + MSGS_URL_STREAM + getConcatStreams(ctx.event().sourceStreams());
	}

	public static String getMessagesUrl(EventNotificationContext ctx, LoggingNotificationConfig config, MessageSummary messageSummary,
			DateTime timeBeginSearch)
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
				search = MSGS_URL_STREAM + concatStream;
			}

    		StringBuilder searchFields = new StringBuilder();
			int i=0;
    		for (String field : config.splitFields()) {
    			String valueAggregationField = (String) messageSummary.getField(field);
    			String prefix;
    			if(i == 0){
					prefix = "&q=";
				}else{
					prefix = "+AND+";
				}
    			if(valueAggregationField != null && !valueAggregationField.isEmpty()) {
    				searchFields.append(prefix + field + "%3A\"" + valueAggregationField + "\"");
    				i++;
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
																			 Map<String, Object> model, DateTime date, MoreSearch moreSearch) {
		Map<String, LoggingAlertFields> listOfLoggingAlertField = Maps.newHashMap();
		String alertID = ctx.event().id();

		for (MessageSummary messageSummary : backlog) {		
			String valuesAggregationField = getValuesAggregationField(messageSummary, config);
			String messagesUrl = getMessagesUrl(ctx, config, messageSummary, date);
			
			if(messageSummary.hasField(config.fieldAlertId())) {
				listOfLoggingAlertField.put(valuesAggregationField,	new LoggingAlertFields((String) messageSummary.getField(config.fieldAlertId()),
						config.severity().getType(), date, messagesUrl));
			}else {
				if(!listOfLoggingAlertField.containsKey(valuesAggregationField)) {
					/* Add hash code if split field */
					String sufix = "";
					if(!valuesAggregationField.equals("")) {
						sufix = "-"+getHashFromString(valuesAggregationField);
					}

					String loggingAlertID = null;
					if(config.aggregationTime() > 0 && config.aggregationStream() != null && !config.aggregationStream().isEmpty()) {
						loggingAlertID = getAggregationAlertID(config, ctx, moreSearch, sufix);
					}
					if(loggingAlertID == null || loggingAlertID.isEmpty()) {
						loggingAlertID = alertID + sufix;
					}

					listOfLoggingAlertField.put(valuesAggregationField,
							 new LoggingAlertFields(loggingAlertID, config.severity().getType(), date, messagesUrl));
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
