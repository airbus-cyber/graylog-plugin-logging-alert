/*
 * Copyright (C) 2018 Airbus CyberSecurity (SAS)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Server Side Public License, version 1,
 * as published by MongoDB, Inc.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Server Side Public License for more details.
 *
 * You should have received a copy of the Server Side Public License
 * along with this program. If not, see
 * <http://www.mongodb.com/licensing/server-side-public-license>.
 */
package com.airbus_cyber_security.graylog.events.notifications.types;

import java.util.*;

import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class MessagesURLBuilderTest {

    private MessagesURLBuilder subject;

    @Before
    public void setup() {
        this.subject = new MessagesURLBuilder();
    }

    @Test
    public void buildSplitFieldsSearchQueryShouldEscapeBackslash() {
        List<String> splitFields = Collections.singletonList("filename");
        Map<String, Object> fields = new HashMap<String, Object>();
        fields.put("_id", "identifier");
        fields.put("filename", "C:\\File.exe");
        Message message = new Message(fields);
        MessageSummary messageSummary = new MessageSummary("index", message);
        String query = this.subject.buildSplitFieldsSearchQuery(splitFields, messageSummary);
        Assert.assertEquals("&q=filename%3A\"C:\\\\File.exe\"", query);
    }

    @Test
    public void buildSplitFieldsSearchQueryShouldEscapeDoubleQuotes() {
        List<String> splitFields = Collections.singletonList("key");
        Map<String, Object> fields = new HashMap<String, Object>();
        fields.put("_id", "identifier");
        fields.put("key", "\"");
        Message message = new Message(fields);
        MessageSummary messageSummary = new MessageSummary("index", message);
        String query = this.subject.buildSplitFieldsSearchQuery(splitFields, messageSummary);
        Assert.assertEquals("&q=key%3A\"\\\"\"", query);
    }

    @Test
    public void buildSplitFieldsSearchQueryShouldNotFailWhenSplitFieldIsInteger() {
        List<String> splitFields = Collections.singletonList("key");
        Map<String, Object> fields = new HashMap<String, Object>();
        fields.put("_id", "identifier");
        fields.put("key", 48);
        Message message = new Message(fields);
        MessageSummary messageSummary = new MessageSummary("index", message);
        this.subject.buildSplitFieldsSearchQuery(splitFields, messageSummary);
    }

    @Test
    public void buildSplitFieldsSearchQueryShouldNotFailWhenSplitFieldIsNotPresent() {
        List<String> splitFields = Collections.singletonList("key");
        Map<String, Object> fields = new HashMap<String, Object>();
        fields.put("_id", "identifier");
        Message message = new Message(fields);
        MessageSummary messageSummary = new MessageSummary("index", message);
        this.subject.buildSplitFieldsSearchQuery(splitFields, messageSummary);
    }
}
