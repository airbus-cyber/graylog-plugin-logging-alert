package com.airbus_cyber_security.graylog;

import org.graylog2.plugin.PluginConfigBean;
import org.graylog2.plugin.PluginModule;

import com.airbus_cyber_security.graylog.config.LoggingAlertConfig;

import java.util.Collections;
import java.util.Set;

/**
 * Extend the PluginModule abstract class here to add you plugin to the system.
 */
public class LoggingAlertModule extends PluginModule {
    /**
     * Returns all configuration beans required by this plugin.
     *
     * Implementing this method is optional. The default method returns an empty {@link Set}.
     */
	
    @Override
    public Set<? extends PluginConfigBean> getConfigBeans() {
        return Collections.emptySet();
    }

    @Override
    protected void configure() {
    	addNotificationType(LoggingAlertConfig.TYPE_NAME, LoggingAlertConfig.class, LoggingAlert.class, LoggingAlert.Factory.class);
    }
}
