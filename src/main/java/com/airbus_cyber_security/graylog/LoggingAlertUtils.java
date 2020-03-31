package com.airbus_cyber_security.graylog;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import com.airbus_cyber_security.graylog.config.LoggingNotificationConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.graylog.events.notifications.EventNotificationContext;
import org.graylog.events.notifications.EventNotificationModelData;
import org.graylog.events.processor.EventDefinitionDto;
import org.graylog.scheduler.JobTriggerDto;
import org.graylog2.indexer.IndexSetRegistry;
import org.graylog2.indexer.indices.Indices;
import org.graylog2.indexer.results.SearchResult;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.indexer.searches.Sorting;
import org.graylog2.jackson.TypeReferences;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.Tools;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.configuration.ConfigurationRequest;
import org.graylog2.plugin.configuration.fields.BooleanField;
import org.graylog2.plugin.configuration.fields.ConfigurationField;
import org.graylog2.plugin.configuration.fields.DropdownField;
import org.graylog2.plugin.configuration.fields.ListField;
import org.graylog2.plugin.configuration.fields.NumberField;
import org.graylog2.plugin.configuration.fields.TextField;
import org.graylog2.plugin.indexer.searches.timeranges.AbsoluteRange;
import org.graylog2.plugin.indexer.searches.timeranges.InvalidRangeParametersException;
import org.graylog2.plugin.indexer.searches.timeranges.RelativeRange;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import com.airbus_cyber_security.graylog.config.SeverityType;
import com.floreysoft.jmte.Engine;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;

public class LoggingAlertUtils {

	private static final String FIELD_SEVERITY = "severity";
	private static final String FIELD_BODY= "content";
	private static final String FIELD_SPLIT = "split_fields";
	private static final String FIELD_COMMENT = "comment";
	private static final String FIELD_AGGREGATION_TIME = "aggregation_time";
	private static final String FIELD_SINGLE_MESSAGE = "single_notification";
	private static final String FIELD_TAG = "alert_tag";
	
	private static final String MSGS_URL_BEGIN = "/search?rangetype=absolute&from=";
	private static final String MSGS_URL_TO = "&to=";
	private static final String MSGS_URL_STREAM = "streams%3A";
	private static final int SIZE_STREAM = 24;
	
	private static final String UNKNOWN = "<unknown>";
	
	private static final Engine templateEngine = new Engine();
	
	public static String buildBody(LoggingNotificationConfig config, Map<String, Object> model) {
		return templateEngine.transform(config.logBody(), model);
	}
	
	public static String getAggregationAlertID(LoggingNotificationConfig config, EventNotificationContext ctx, Searches searches, String sufixID) {
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
			e.printStackTrace();
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
    
	public static String getValuesAggregationField(MessageSummary messageSummary, Configuration configuration) {
    	StringBuilder valuesAggregationField = new StringBuilder();
    	for (String field : configuration.getList(FIELD_SPLIT, Collections.emptyList())) {
			valuesAggregationField.append(messageSummary.getField(field));
		}
    	return valuesAggregationField.toString();
    }
    
	public static String getAlertUrl(EventNotificationContext ctx)
    {
    	if (ctx.eventDefinition().isPresent()) {
    		return "/event/"+ctx.eventDefinition().get().id();
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
		return MSGS_URL_BEGIN
				+ timeBeginSearch.minusMinutes(1).toString(timeFormatter) + MSGS_URL_TO
				+ ctx.jobTrigger().get().triggeredAt().get().plusMinutes(1).toString(timeFormatter)
				+ "&q=streams%3A" + ctx.event().id();
	}

	public static String getMessagesUrl(EventNotificationContext ctx, final Configuration configuration, Map <String, Object> conditionParameters, MessageSummary messageSummary, 
			DateTime timeBeginSearch, Searches searches)
    {
    	DateTimeFormatter timeFormatter = DateTimeFormat.forPattern("yyy-MM-dd'T'HH'%3A'mm'%3A'ss.SSS'Z'");
    	if(ctx.eventDefinition().isPresent()) {

    		DateTime endTime;
    		/* If the alert is interval and resolved */
    		if(ctx.jobTrigger().isPresent() && ctx.jobTrigger().get().endTime() != null) {
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

    		String search = "&q=streams%3A" + ctx.notificationId();
    		if(conditionParameters.containsKey("additional_stream")) {
    			String additionalStreamID = (String) conditionParameters.get("additional_stream");

    			String previousMsgsURL =  getPreviousMessagesURL(additionalStreamID, beginTime, endTime, searches);
    			if(previousMsgsURL!= null && !previousMsgsURL.isEmpty()) {
    				DateTime timeFromMsgsUrl = getTimeFrom(previousMsgsURL, timeFormatter);
    				if(timeFromMsgsUrl != null && timeFromMsgsUrl.isBefore(beginTime)){
    					beginTime = timeFromMsgsUrl;
    				}
    				search = "&q=(+streams%3A" + ctx.notificationId() + getQuery(previousMsgsURL) + "+)";
    			}
    		}

    		StringBuilder searchFields = new StringBuilder();
    		for (String field : configuration.getList(FIELD_SPLIT, Collections.emptyList())) {
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
							 Map<String, Object> model, DateTime date, Configuration configuration, Searches searches) {
    	String alertUrl = getAlertUrl(ctx);
    	Map<String, LoggingAlertFields> listOfLoggingAlertField = Maps.newHashMap();

		for (MessageSummary messageSummary : backlog) {		
			String valuesAggregationField = getValuesAggregationField(messageSummary, configuration);
			String messagesUrl = getMessagesUrl(ctx, configuration, model, messageSummary, date, searches);
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
									  final Map<String, Object> model, LoggingAlertFields loggingAlertFields) {
		model.put("logging_alert", loggingAlertFields);
		String messageToLog=buildBody(config, model);
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
    
	private static ConfigurationRequest getRequestedConfiguration(LoggingNotificationConfig config, final Indices indices, final IndexSetRegistry indexSetRegistry) {
    	final ConfigurationRequest configurationRequest = new ConfigurationRequest();
		final String[] writeIndexWildcards = indexSetRegistry.getIndexWildcards();
        final Set<String> listFields = indices.getAllMessageFields(writeIndexWildcards);    
        Map<String, String> mapFields = listFields.stream().collect(Collectors.toMap(x -> x, x -> x));

		LinkedHashMap<String, String> severity = new LinkedHashMap<>();
		severity.put(SeverityType.HIGH.getType(), "high");
		severity.put(SeverityType.MEDIUM.getType(), "medium");
		severity.put(SeverityType.LOW.getType(), "low");
		severity.put(SeverityType.INFO.getType(), "info");
			    
		configurationRequest.addField(new DropdownField(FIELD_SEVERITY, 
				"Alert Severity", 
				severity.get(config.severity().getType()),
				severity,
				"The severity of logged alerts",
				ConfigurationField.Optional.NOT_OPTIONAL));
		
		configurationRequest.addField(new TextField(FIELD_BODY,
                "Log Content",
                config.logBody(),
                "The template to generate the log content from",
                ConfigurationField.Optional.NOT_OPTIONAL,
                TextField.Attribute.TEXTAREA));
		
		configurationRequest.addField(new ListField(FIELD_SPLIT,
				"Split Fields", 
				Collections.emptyList(), 
        		mapFields.entrySet().stream().sorted(Map.Entry.comparingByValue()).
        		collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue,(e1, e2) -> e1, LinkedHashMap::new)),
        		"Fields that should be checked to split the alert according to each value by generating a different alert id for each value", 
        		ConfigurationField.Optional.OPTIONAL,
        		ListField.Attribute.ALLOW_CREATE));
		
		configurationRequest.addField(new NumberField(FIELD_AGGREGATION_TIME, 
				"Aggregation Time Range", 
				config.aggregationTime(), 
        		"Aggregate alerts received in the given number of minutes by logging alerts with the same alert id", 
        		ConfigurationField.Optional.OPTIONAL,
        		NumberField.Attribute.ONLY_POSITIVE));

		configurationRequest.addField(new TextField(FIELD_TAG,
				"Alert Tag",
				config.alertTag(),
				"The tag of the generated logs",
				ConfigurationField.Optional.OPTIONAL));

		configurationRequest.addField(new BooleanField(FIELD_SINGLE_MESSAGE,
				"Single message",
				false,
				"Check this box to send only one message by alert"));

		configurationRequest.addField(new TextField(FIELD_COMMENT,
                "Comment",
                "",
                "Comment about the configuration",
                ConfigurationField.Optional.OPTIONAL));
		
    	return configurationRequest;
    }
    
	public static Configuration getConfiguration(final LoggingNotificationConfig config, final Indices indices, final IndexSetRegistry indexSetRegistry) {
    	ConfigurationRequest configurationRequest = getRequestedConfiguration(config, indices, indexSetRegistry);
    	Map<String, ConfigurationField> fields = configurationRequest.getFields();
    	Map<String, Object> mapConfigFields = new HashMap<>();
    	for(Map.Entry<String, ConfigurationField> entry : fields.entrySet()) {
    		mapConfigFields.put(entry.getKey(), entry.getValue());
    	}
    	return new Configuration(mapConfigFields);
    }
}
