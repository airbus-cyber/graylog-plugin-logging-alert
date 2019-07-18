package com.airbus_cyber_security.graylog;

import org.graylog2.plugin.PluginMetaData;
import org.graylog2.plugin.ServerStatus;
import org.graylog2.plugin.Version;

import java.net.URI;
import java.util.Collections;
import java.util.Set;

/**
 * Implement the PluginMetaData interface here.
 */
public class LoggingAlertMetaData implements PluginMetaData {
	private static final String PLUGIN_PROPERTIES = "com.airbus-cyber-security.graylog.graylog-plugin-logging-alert/graylog-plugin.properties";
	
    @Override
    public String getUniqueId() {
        return "com.airbus-cyber-security.graylog.LoggingAlertPlugin";
    }

    @Override
    public String getName() {
        return "Logging Alert Notification";
    }

    @Override
    public String getAuthor() {
        return "Airbus CyberSecurity";
    }

    @Override
    public URI getURL() {
        return URI.create("https://www.airbus-cyber-security.com");
    }

    @Override
    public Version getVersion() {
    	return Version.fromPluginProperties(getClass(), PLUGIN_PROPERTIES, "version", Version.from(0, 0, 1, "unknown"));
    }

    @Override
    public String getDescription() {
        return "This notification generates a log message when an alert is triggered.";
    }

    @Override
    public Version getRequiredVersion() {
    	return Version.fromPluginProperties(getClass(), PLUGIN_PROPERTIES, "graylog.version", Version.from(3, 0, 0));
    }

    @Override
    public Set<ServerStatus.Capability> getRequiredCapabilities() {
        return Collections.emptySet();
    }
}
