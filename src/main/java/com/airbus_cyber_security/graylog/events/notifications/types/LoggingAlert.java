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

import com.airbus_cyber_security.graylog.events.config.LoggingAlertConfig;
import com.airbus_cyber_security.graylog.events.storage.MessagesSearches;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import org.graylog.events.notifications.*;
import org.graylog.events.event.EventDto;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.*;

/**
 * This is the plugin. Your class should implement one of the existing plugin
 * interfaces. (i.e. AlarmCallback, MessageInput, MessageOutput)
 * UPDATE Graylog 3.2 : the class should implement EventNotification
 */
public class LoggingAlert implements EventNotification {

    private static final Logger LOGGER = LoggerFactory.getLogger(LoggingAlert.class);

    private static final String SEPARATOR_TEMPLATE = "\n";

    private final EventNotificationService notificationCallbackService;

    private final ClusterConfigService clusterConfigService;


    private final MessageBodyBuilder messageBodyBuilder;

    public interface Factory extends EventNotification.Factory {
        @Override
        LoggingAlert create();
    }

    @Inject
    public LoggingAlert(ClusterConfigService clusterConfigService, EventNotificationService notificationCallbackService,
                        MessageBodyBuilder messageBodyBuilder) {
        this.notificationCallbackService = notificationCallbackService;
        this.clusterConfigService = clusterConfigService;
        this.messageBodyBuilder = messageBodyBuilder;
    }

    @Override
    public void execute(EventNotificationContext context) {
        LOGGER.debug("Start of execute...");
        LoggingAlertConfig generalConfig = this.clusterConfigService.getOrDefault(LoggingAlertConfig.class, LoggingAlertConfig.createDefault());
        LoggingNotificationConfig config = (LoggingNotificationConfig) context.notificationConfig();
        ImmutableList<MessageSummary> backlog = this.notificationCallbackService.getBacklogForEvent(context);
        String logTemplate = config.logBody().replace(SEPARATOR_TEMPLATE, generalConfig.accessSeparator());

        EventDto event = context.event();
        DateTime date = event.eventTimestamp();

        for (MessageSummary messageSummary: backlog) {
            if (messageSummary.getTimestamp().isBefore(date))
                date = messageSummary.getTimestamp();
        }

        Collection<String> listMessagesToLog = new ArrayList<>();
        if (backlog.isEmpty() || config.singleMessage()) {
            LOGGER.debug("Add log to list message for empty backlog or single message...");
            LoggingAlertFields loggingAlertFields = new LoggingAlertFields(
                    this.messageBodyBuilder.getAlertID(config, generalConfig, context),
                    config.severity().getType(),
                    date,
                    this.messageBodyBuilder.getStreamSearchUrl(event, date));

            String messageToLog = this.messageBodyBuilder.buildMessageBodyForBacklog(logTemplate, context, backlog, loggingAlertFields);
            listMessagesToLog.add(messageToLog);
        } else {
            LOGGER.debug("Add log to list message for backlog...");
            for (MessageSummary message: backlog) {
                String messageToLog = this.messageBodyBuilder.buildMessageBodyForMessage(logTemplate, context, config, generalConfig, date, message);
                listMessagesToLog.add(messageToLog);
            }
        }

        Logger localLogger = LoggerFactory.getLogger(config.alertTag());
        Logger loggerOverflow = LoggerFactory.getLogger(generalConfig.accessOverflowTag());

        /* Log each messages */
        int iter = 0;
        for (String message: listMessagesToLog) {
            if (generalConfig.accessLimitOverflow() <= 0 || iter < generalConfig.accessLimitOverflow()) {
                localLogger.info(message);
            } else {
                loggerOverflow.info(message);
            }
            iter++;
        }

        LOGGER.debug("End of execute...");
    }
}
