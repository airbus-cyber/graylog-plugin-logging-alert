package com.airbus_cyber_security.graylog;

import java.util.*;
import java.util.stream.Collectors;

import org.graylog2.alerts.Alert;
import org.graylog2.alerts.AlertService;
import org.graylog2.indexer.IndexSetRegistry;
import org.graylog2.indexer.indices.Indices;
import org.graylog2.indexer.results.SearchResult;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.indexer.searches.Sorting;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.Tools;
import org.graylog2.plugin.alarms.AlertCondition;
import org.graylog2.plugin.alarms.AlertCondition.CheckResult;
import org.graylog2.plugin.alarms.callbacks.AlarmCallback;
import org.graylog2.plugin.alarms.callbacks.AlarmCallbackConfigurationException;
import org.graylog2.plugin.alarms.callbacks.AlarmCallbackException;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.configuration.ConfigurationException;
import org.graylog2.plugin.configuration.ConfigurationRequest;
import org.graylog2.plugin.configuration.fields.ConfigurationField;
import org.graylog2.plugin.configuration.fields.DropdownField;
import org.graylog2.plugin.configuration.fields.ListField;
import org.graylog2.plugin.configuration.fields.NumberField;
import org.graylog2.plugin.configuration.fields.TextField;
import org.graylog2.plugin.indexer.searches.timeranges.AbsoluteRange;
import org.graylog2.plugin.indexer.searches.timeranges.InvalidRangeParametersException;
import org.graylog2.plugin.indexer.searches.timeranges.RelativeRange;
import org.graylog2.plugin.streams.Stream;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.airbus_cyber_security.graylog.config.LoggingAlertConfig;
import com.airbus_cyber_security.graylog.config.SeverityType;
import com.floreysoft.jmte.Engine;
import com.google.common.collect.Maps;
import com.google.inject.Inject;

/**
 * This is the plugin. Your class should implement one of the existing plugin
 * interfaces. (i.e. AlarmCallback, MessageInput, MessageOutput)
 */
public class LoggingAlert implements AlarmCallback{
	
	private final Logger LOGGER;
	private final Logger LOGGER_OVERFLOW;
	
	private static final String FIELD_SEVERITY = "severity";
	private static final String FIELD_BODY= "content";
	private static final String FIELD_SPLIT = "split_fields";
	private static final String FIELD_COMMENT = "comment";
	private static final String FIELD_AGGREGATION_TIME = "aggregation_time";
	
	private static final String SEPARATOR_TEMPLATE = "\n";
	
	private static final String MSGS_URL_BEGIN = "/search?rangetype=absolute&from=";
	private static final String MSGS_URL_TO = "&to=";
	private static final String MSGS_URL_STREAM = "streams%3A";
	private static final int SIZE_STREAM = 24;
	
	
	private final Engine templateEngine = new Engine();
	private final ClusterConfigService clusterConfigService;
	private Configuration configs;
	private final Indices indices;
	private final IndexSetRegistry indexSetRegistry;
	private final AlertService alertService;
	private final Searches searches;
	private final String fieldAlertID;
	private final String aggregationStreamID;
	private final int limitOverflow;
	private final String separator;
	
	@Inject
    public LoggingAlert(final ClusterConfigService clusterConfigService, Indices indices, IndexSetRegistry indexSetRegistry, 
    		AlertService alertService, Searches searches) {
	this.clusterConfigService = clusterConfigService;
	this.indices = indices;
        this.indexSetRegistry = indexSetRegistry;
        this.alertService = alertService;
        this.searches = searches;
        
        final LoggingAlertConfig configGeneral = clusterConfigService.getOrDefault(LoggingAlertConfig.class,
				LoggingAlertConfig.createDefault());
    	
    	aggregationStreamID = configGeneral.accessAggregationStream();
    	fieldAlertID = configGeneral.accessFieldAlertId();    	
    	limitOverflow = configGeneral.accessLimitOverflow();
    	separator = configGeneral.accessSeparator();
    	
    	LOGGER = LoggerFactory.getLogger(configGeneral.accessAlertTag());
    	LOGGER_OVERFLOW = LoggerFactory.getLogger(configGeneral.accessOverflowTag());
    }

    private Map<String, Object> getModel(Stream stream, AlertCondition.CheckResult checkResult, 
    		Message message, LoggingAlertFields loggingAlertFields) {
        Map<String, Object> model = new HashMap<>();
        model.put("message", message);
        model.put("stream", stream);
        model.put("check_result", checkResult);
        model.put("alertCondition", checkResult.getTriggeredCondition());
        model.put("logging_alert", loggingAlertFields);
        
        return model;
    }
    
    private String buildBody(Stream stream, AlertCondition.CheckResult checkResult, Message message, LoggingAlertFields loggingAlertFields) {
        Map<String, Object> model = getModel(stream, checkResult, message, loggingAlertFields);
        return this.templateEngine.transform(configs.getString(FIELD_BODY).replace(SEPARATOR_TEMPLATE, separator), model);
    }
	
    
    private String getAggregationAlertID(Stream stream, DateTime date, String sufixID) {
		try {
			RelativeRange relativeRange = RelativeRange.create(configs.getInt(FIELD_AGGREGATION_TIME) * 60);
			final AbsoluteRange range = AbsoluteRange.create(relativeRange.getFrom(), relativeRange.getTo());
			
			final String filter = "streams:" + aggregationStreamID;
			List<Alert> listAlert = alertService.loadRecentOfStream(stream.getId(), 
					date.minusMinutes(configs.getInt(FIELD_AGGREGATION_TIME)), 300);
			if(!listAlert.isEmpty()) {
				Iterator<Alert> it = listAlert.iterator();
				StringBuilder bldStringsearchQuery = new StringBuilder(fieldAlertID+": "+it.next().getId()+sufixID);
				while (it.hasNext()) {
					bldStringsearchQuery.append(" OR "+fieldAlertID+": "+it.next().getId()+sufixID);
				}
				
		    	final SearchResult backlogResult = searches.search(bldStringsearchQuery.toString(), filter,
						range, 10, 0, new Sorting(Message.FIELD_TIMESTAMP, Sorting.Direction.DESC));
		    	
		    	if(!backlogResult.getResults().isEmpty()) {
		    		return backlogResult.getResults().get(0).getMessage().getField(fieldAlertID).toString();
		    	}
			}
		} catch (InvalidRangeParametersException e) {
			e.printStackTrace();
		}
    	return null;
    }
    
    private String getGraylogID(Stream stream, CheckResult result) {
    	Optional<Alert> optionalAlert = alertService.getLastTriggeredAlert(stream.getId(), result.getTriggeredCondition().getId());
		if(optionalAlert.isPresent()) {
			return optionalAlert.get().getId();
		}else {
			return null;
		}
    }
    
    private String getNewAlertID(Stream stream, CheckResult result) {
    	String graylogID = getGraylogID(stream, result);		
    	if(graylogID != null) {
			return graylogID;
		}else {
			return UUID.randomUUID().toString();
		}
    }
    
    private String getAlertID(Stream stream, CheckResult result, String sufixID) {
    	String loggingAlertID = null;
    	    	
		if(configs.intIsSet(FIELD_AGGREGATION_TIME) && configs.getInt(FIELD_AGGREGATION_TIME) > 0 && 
				aggregationStreamID != null && !aggregationStreamID.isEmpty()) {
			loggingAlertID = getAggregationAlertID(stream, result.getTriggeredAt(), sufixID);
		}
		
		if(loggingAlertID == null || loggingAlertID.isEmpty()) {
			loggingAlertID = getNewAlertID(stream, result) + sufixID;
		}
		return loggingAlertID;
    }
    
    private String getValuesAggregationField(MessageSummary messageSummary) {
    	StringBuilder valuesAggregationField = new StringBuilder();
    	for (String field : configs.getList(FIELD_SPLIT, Collections.emptyList())) {
			valuesAggregationField.append(messageSummary.getField(field));
		}
    	return valuesAggregationField.toString();
    }
    
    private String getAlertUrl(Stream stream, CheckResult result)
    {
    	Optional<Alert> optionalAlert = alertService.getLastTriggeredAlert(stream.getId(), result.getTriggeredCondition().getId());
		if(optionalAlert.isPresent()) {
			return "/alerts/"+optionalAlert.get().getId();
		}
		return "";
    }
    
    private String getPreviousMessagesURL(String streamID, DateTime timeBegin, DateTime timeEnd) {
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
    
    private DateTime getTimeFrom(String msgsURL, DateTimeFormatter timeFormatter) {   	
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
    
    private String getQuery(String msgsURL) {
    	StringBuilder query = new StringBuilder();
    	int indexBegin = msgsURL.indexOf(MSGS_URL_STREAM);
    	while(indexBegin > 0) {
    		int indexEnd = indexBegin + MSGS_URL_STREAM.length() + SIZE_STREAM;
    		query.append("+OR+" + msgsURL.substring(indexBegin, indexEnd));
    		indexBegin = msgsURL.indexOf(MSGS_URL_STREAM, indexEnd);
    	}
    	
    	return query.toString();
    }

	private String getStreamSearchUrl(Stream stream, CheckResult result, DateTime timeBeginSearch){
		DateTimeFormatter timeFormatter = DateTimeFormat.forPattern("yyy-MM-dd'T'HH'%3A'mm'%3A'ss.SSS'Z'");
		return MSGS_URL_BEGIN
				+ timeBeginSearch.minusMinutes(1).toString(timeFormatter) + MSGS_URL_TO
				+ result.getTriggeredAt().plusMinutes(1).toString(timeFormatter)
				+ "&q=streams%3A" + stream.getId();
	}

    private String getMessagesUrl(Stream stream, CheckResult result, MessageSummary messageSummary, DateTime timeBeginSearch)
    {
    	DateTimeFormatter timeFormatter = DateTimeFormat.forPattern("yyy-MM-dd'T'HH'%3A'mm'%3A'ss.SSS'Z'");
    	Optional<Alert> optionalAlert = alertService.getLastTriggeredAlert(stream.getId(), result.getTriggeredCondition().getId());
    	if(optionalAlert.isPresent()) {

    		DateTime endTime;
    		/* If the alert is interval and resolved */
    		if(optionalAlert.get().isInterval() && optionalAlert.get().getResolvedAt() != null) {
    			endTime = optionalAlert.get().getResolvedAt().plusMinutes(1);
    		}else {
    			endTime = optionalAlert.get().getTriggeredAt().plusMinutes(1);
    		}

    		/* when the alert is unresolved and the repeat notification is active */
	    	int timeRange = Tools.getNumber(result.getTriggeredCondition().getParameters().get("time"), 1).intValue();
	    	if(endTime.isBefore(timeBeginSearch.plusMinutes(timeRange))) {
	    		endTime = timeBeginSearch.plusMinutes(timeRange);
	    	}

    		DateTime beginTime = timeBeginSearch;

    		String search = "&q=streams%3A" + stream.getId();
    		Map <String, Object> conditionParameters = optionalAlert.get().getConditionParameters();
    		if(conditionParameters.containsKey("additional_stream")) {
    			String additionalStreamID = (String) conditionParameters.get("additional_stream");

    			String previousMsgsURL =  getPreviousMessagesURL(additionalStreamID, beginTime, endTime);
    			if(previousMsgsURL!= null && !previousMsgsURL.isEmpty()) {
    				DateTime timeFromMsgsUrl = getTimeFrom(previousMsgsURL, timeFormatter);
    				if(timeFromMsgsUrl != null && timeFromMsgsUrl.isBefore(beginTime)){
    					beginTime = timeFromMsgsUrl;
    				}
    				search = "&q=(+streams%3A" + stream.getId() + getQuery(previousMsgsURL) + "+)";
    			}
    		}

    		StringBuilder searchFields = new StringBuilder();
    		for (String field : configs.getList(FIELD_SPLIT, Collections.emptyList())) {
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

		return getStreamSearchUrl(stream, result, timeBeginSearch);
    }
    
    private String getHashFromString(String value) {
    	int hash = value.hashCode();
		if(hash < 0) {
			return "a"+Math.abs(hash);
		}
    	return String.valueOf(hash);
    }
    
    private Map<String, LoggingAlertFields> getListOfloggingAlertField(Stream stream, CheckResult result, DateTime date) {
    	String graylogId = getGraylogID(stream, result);
    	String alertUrl = getAlertUrl(stream, result);
    	Map<String, LoggingAlertFields> listOfloggingAlertField = Maps.newHashMap();

		for (MessageSummary messageSummary : result.getMatchingMessages()) {		
			String valuesAggregationField = getValuesAggregationField(messageSummary);
			String messagesUrl = getMessagesUrl(stream, result, messageSummary, date);
			
			if(messageSummary.hasField(fieldAlertID)) {
				listOfloggingAlertField.put(valuesAggregationField,	new LoggingAlertFields((String) messageSummary.getField(fieldAlertID), 
						graylogId, configs.getString(FIELD_SEVERITY), date, alertUrl, messagesUrl));
			}else {	
				if(!listOfloggingAlertField.containsKey(valuesAggregationField)) {
					/* Add hash code if split field */
					String alertID = null;
					if(valuesAggregationField.equals("")) {
						alertID = getAlertID(stream, result, "");
					}else {
						alertID = getAlertID(stream, result, "-"+getHashFromString(valuesAggregationField));
					}
					listOfloggingAlertField.put(valuesAggregationField,
							 new LoggingAlertFields(alertID, graylogId, configs.getString(FIELD_SEVERITY), date, alertUrl, messagesUrl));
				}	
			}
		}
		
		return listOfloggingAlertField;
    }
    
	@Override
	public void call(Stream stream, CheckResult result)
			throws AlarmCallbackException {

		/* Get the time of the first message */
		List<MessageSummary> listMsgSummary = result.getMatchingMessages();
		DateTime date = result.getTriggeredAt();
		for (MessageSummary messageSummary : listMsgSummary) {
			if(messageSummary.getTimestamp().isBefore(date))
				date = messageSummary.getTimestamp();
		}

		/* Get the list of messages to log */
		Set<String> listMessagesToLog= new LinkedHashSet<>();
		if(listMsgSummary.isEmpty()) {
			LoggingAlertFields loggingAlertFields= new LoggingAlertFields( getAlertID(stream, result, ""), 
					getGraylogID(stream, result), configs.getString(FIELD_SEVERITY), date, getAlertUrl(stream, result), getStreamSearchUrl(stream, result, date));
			String messageToLog=buildBody(stream, result, new Message("Empty message", "LoggingAlert", date), loggingAlertFields);
			listMessagesToLog.add(messageToLog);
		}else {
			Map<String, LoggingAlertFields> listOfloggingAlertField = getListOfloggingAlertField(stream, result, date);
			for (MessageSummary messageSummary : listMsgSummary) {	
				String valuesAggregationField = getValuesAggregationField(messageSummary);
				String messageToLog=buildBody(stream, result, messageSummary.getRawMessage(), 
						listOfloggingAlertField.get(valuesAggregationField));
				listMessagesToLog.add(messageToLog);
			}
		}
		
		/* Log each messages */
		int iter = 0;
		for (String message : listMessagesToLog) {
			if(limitOverflow <= 0 || iter < limitOverflow) {
				LOGGER.info(message);
			} else {
				LOGGER_OVERFLOW.info(message);
			}
			iter++;
		}
	}

	@Override
	public void checkConfiguration() throws ConfigurationException {
		
	}

	@Override
	public Map<String, Object> getAttributes() {
		return configs.getSource();
	}

	@Override
	public String getName() {
		return "Logging Alert Notification";
	}

	@Override
	public ConfigurationRequest getRequestedConfiguration() {
		final ConfigurationRequest configurationRequest = new ConfigurationRequest();
		final LoggingAlertConfig configGeneral = clusterConfigService.getOrDefault(LoggingAlertConfig.class,
				LoggingAlertConfig.createDefault());
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
				severity.get(configGeneral.accessSeverity().getType()),
				severity,
				"The severity of logged alerts",
				ConfigurationField.Optional.NOT_OPTIONAL));
		
		configurationRequest.addField(new TextField(FIELD_BODY,
                "Log Content",
                configGeneral.accessLogBody(),
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
				configGeneral.accessAggregationTime(), 
        		"Aggregate alerts received in the given number of minutes by logging alerts with the same alert id", 
        		ConfigurationField.Optional.OPTIONAL,
        		NumberField.Attribute.ONLY_POSITIVE));
		
		configurationRequest.addField(new TextField(FIELD_COMMENT,
                "Comment",
                "",
                "Comment about the configuration",
                ConfigurationField.Optional.OPTIONAL));
		
		return configurationRequest;
	}

	@Override
	public void initialize(Configuration arg0)
			throws AlarmCallbackConfigurationException {
		configs = new Configuration(arg0.getSource());
    }
	
}
