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
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import com.google.inject.Inject;
import org.graylog.events.notifications.EventNotification;
import org.graylog.events.notifications.EventNotificationContext;
import org.graylog.events.notifications.EventNotificationService;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

    private final LoggingAlertUtils loggingAlertUtils;

    public interface Factory extends EventNotification.Factory {
        @Override
        LoggingAlert create();
    }

    @Inject
    public LoggingAlert(ClusterConfigService clusterConfigService, EventNotificationService notificationCallbackService,
                        ObjectMapper objectMapper, Searches searches) {
        this.notificationCallbackService = notificationCallbackService;
        this.clusterConfigService = clusterConfigService;
        this.loggingAlertUtils = new LoggingAlertUtils(objectMapper, searches);
    }

    @Override
    public void execute(EventNotificationContext ctx) {
        LOGGER.debug("Start of execute...");
        LoggingAlertConfig generalConfig = this.clusterConfigService.getOrDefault(LoggingAlertConfig.class, LoggingAlertConfig.createDefault());
        LoggingNotificationConfig config = (LoggingNotificationConfig) ctx.notificationConfig();
        ImmutableList<MessageSummary> backlog = this.notificationCallbackService.getBacklogForEvent(ctx);
        String logTemplate = config.logBody().replace(SEPARATOR_TEMPLATE, generalConfig.accessSeparator());

        DateTime date = ctx.event().eventTimestamp();

        for (MessageSummary messageSummary: backlog) {
            if (messageSummary.getTimestamp().isBefore(date))
                date = messageSummary.getTimestamp();
        }

        Collection<String> listMessagesToLog = new ArrayList<>();
        if (backlog.isEmpty() || config.singleMessage()) {
            LOGGER.debug("Add log to list message for empty backlog or single message...");
            LoggingAlertFields loggingAlertFields = new LoggingAlertFields(
                    this.loggingAlertUtils.getAlertID(config, generalConfig, ctx),
                    config.severity().getType(),
                    date,
                    LoggingAlertUtils.getStreamSearchUrl(ctx, date));

            String messageToLog = this.loggingAlertUtils.buildMessageBody(logTemplate, ctx, backlog, loggingAlertFields);
            listMessagesToLog.add(messageToLog);
        } else {
            LOGGER.debug("Add log to list message for backlog...");
            Map<String, LoggingAlertFields> listOfloggingAlertField =
                    this.loggingAlertUtils.getListOfLoggingAlertField(ctx, backlog, config, generalConfig, date);
            for (MessageSummary message: backlog) {
                String valuesAggregationField = LoggingAlertUtils.getValuesAggregationField(message, config);
                LoggingAlertFields loggingAlertFields = listOfloggingAlertField.get(valuesAggregationField);
                ImmutableList<MessageSummary> backlogWithMessage = new ImmutableList.Builder<MessageSummary>().add(message).build();

                String messageToLog = this.loggingAlertUtils.buildMessageBody(logTemplate, ctx, backlogWithMessage, loggingAlertFields);
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
