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

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * This is the plugin. Your class should implement one of the existing plugin
 * interfaces. (i.e. AlarmCallback, MessageInput, MessageOutput)
 * UPDATE Graylog 3.2 : the class should implement EventNotification
 */
public class LoggingAlert implements EventNotification {

    private static final Logger LOGGER = LoggerFactory.getLogger(LoggingAlert.class);

    private final EventNotificationService notificationCallbackService;

    private final ObjectMapper objectMapper;

    private final ClusterConfigService clusterConfigService;

    private final Searches searches;

    public interface Factory extends EventNotification.Factory {
        @Override
        LoggingAlert create();
    }

    @Inject
    public LoggingAlert(ClusterConfigService clusterConfigService, EventNotificationService notificationCallbackService,
                        ObjectMapper objectMapper, Searches searches) {
        this.notificationCallbackService = notificationCallbackService;
        this.objectMapper = objectMapper;
        this.clusterConfigService = clusterConfigService;
        this.searches = searches;
    }

    @Override
    public void execute(EventNotificationContext ctx) {
        LOGGER.debug("Start of execute...");
        final LoggingAlertConfig generalConfig = clusterConfigService.getOrDefault(LoggingAlertConfig.class, LoggingAlertConfig.createDefault());
        final LoggingNotificationConfig config = (LoggingNotificationConfig) ctx.notificationConfig();
        final ImmutableList<MessageSummary> backlog = notificationCallbackService.getBacklogForEvent(ctx);

        DateTime date = ctx.event().eventTimestamp();

        for (MessageSummary messageSummary : backlog) {
            if (messageSummary.getTimestamp().isBefore(date))
                date = messageSummary.getTimestamp();
        }

        Set<String> listMessagesToLog = new LinkedHashSet<>();
        Map<String, Object> model = LoggingAlertUtils.getModel(ctx, backlog, objectMapper);

        if (backlog.isEmpty() || config.singleMessage()) {
            LOGGER.debug("Add log to list message for empty backlog or single message...");
            LoggingAlertFields loggingAlertFields = new LoggingAlertFields(
                    LoggingAlertUtils.getAlertID(config, generalConfig, ctx, searches, ""),
                    config.severity().getType(),
                    date,
                    LoggingAlertUtils.getStreamSearchUrl(ctx, date));
            LoggingAlertUtils.addLogToListMessages(config, listMessagesToLog, model, loggingAlertFields, generalConfig.accessSeparator());
        } else {
            LOGGER.debug("Add log to list message for backlog...");
            Map<String, LoggingAlertFields> listOfloggingAlertField =
                    LoggingAlertUtils.getListOfLoggingAlertField(ctx, backlog, config, generalConfig, date, searches);
            for (MessageSummary messageSummary : backlog) {
                model = LoggingAlertUtils.getModel(ctx, messageSummary, objectMapper);
                String valuesAggregationField = LoggingAlertUtils.getValuesAggregationField(messageSummary, config);
                LoggingAlertFields loggingAlertFields = listOfloggingAlertField.get(valuesAggregationField);
                LoggingAlertUtils.addLogToListMessages(config, listMessagesToLog, model, loggingAlertFields, generalConfig.accessSeparator());
            }
        }

        final Logger localLogger = LoggerFactory.getLogger(config.alertTag());
        final Logger loggerOverflow = LoggerFactory.getLogger(generalConfig.accessOverflowTag());

        /* Log each messages */
        int iter = 0;
        for (String message : listMessagesToLog) {
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
