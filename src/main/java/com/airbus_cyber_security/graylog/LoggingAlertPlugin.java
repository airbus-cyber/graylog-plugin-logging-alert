package com.airbus_cyber_security.graylog;

import com.airbus_cyber_security.graylog.events.LoggingAlertModule;
import org.graylog2.plugin.Plugin;
import org.graylog2.plugin.PluginMetaData;
import org.graylog2.plugin.PluginModule;

import java.util.Arrays;
import java.util.Collection;

/**
 * Implement the Plugin interface here.
 */
public class LoggingAlertPlugin implements Plugin {
    @Override
    public PluginMetaData metadata() {
        return new LoggingAlertMetaData();
    }

    @Override
    public Collection<PluginModule> modules () {
        return Arrays.<PluginModule>asList(new LoggingAlertModule());
    }
}
