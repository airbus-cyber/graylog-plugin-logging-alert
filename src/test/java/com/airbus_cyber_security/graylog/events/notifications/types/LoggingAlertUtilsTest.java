package com.airbus_cyber_security.graylog.events.notifications.types;


import java.util.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

public class LoggingAlertUtilsTest {

    private LoggingAlertUtils subject;

    @Before
    public void setup() {
        ObjectMapper objectMapper = Mockito.mock(ObjectMapper.class);
        Searches searches = Mockito.mock(Searches.class);
        this.subject = new LoggingAlertUtils(objectMapper, searches);
    }

    @Test
    public void buildSearchQueryShouldEscapeBackslash() {
        List<String> splitFields = Collections.singletonList("filename");
        Map<String, Object> fields = new HashMap<String, Object>();
        fields.put("_id", "identifier");
        fields.put("filename", "C:\\File.exe");
        Message message = new Message(fields);
        MessageSummary messageSummary = new MessageSummary("index", message);
        String query = subject.buildSearchQuery(splitFields, messageSummary);
        Assert.assertEquals("&q=filename%3A\"C:\\File.exe\"", query);
    }
}
