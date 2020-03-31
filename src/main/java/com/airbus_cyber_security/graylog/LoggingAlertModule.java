package com.airbus_cyber_security.graylog;

import com.airbus_cyber_security.graylog.config.LoggingNotificationConfig;
import org.graylog2.plugin.PluginConfigBean;
import org.graylog2.plugin.PluginModule;

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
    	addNotificationType(LoggingNotificationConfig.TYPE_NAME, LoggingNotificationConfig.class, LoggingAlert.class, LoggingAlert.Factory.class);
    }
}
