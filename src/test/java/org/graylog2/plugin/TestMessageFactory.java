package org.graylog2.plugin;

import java.util.Map;

public class TestMessageFactory {
    public static Message createMessage(Map<String, Object> fields) {
        return new Message(fields);
    }
}
