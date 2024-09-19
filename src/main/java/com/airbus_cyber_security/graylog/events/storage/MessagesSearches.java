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
package com.airbus_cyber_security.graylog.events.storage;

import org.graylog2.indexer.results.SearchResult;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.indexer.searches.Sorting;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.indexer.searches.timeranges.AbsoluteRange;
import org.graylog2.plugin.indexer.searches.timeranges.InvalidRangeParametersException;
import org.graylog2.plugin.indexer.searches.timeranges.RelativeRange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.inject.Inject;
import java.text.MessageFormat;
import java.util.Locale;


public class MessagesSearches {

    private static final Logger LOGGER = LoggerFactory.getLogger(MessagesSearches.class);

    private final Searches searches;

    @Inject
    public MessagesSearches(Searches searches) {
        this.searches = searches;
    }

    public String getAggregationAlertIdentifier(int aggregationTime, String alertIdentifierFieldName, String aggregationStream, String suffixID) {
        LOGGER.debug("Start of getAggregationAlertID...");
        try {
            RelativeRange relativeRange = RelativeRange.create(aggregationTime * 60);
            AbsoluteRange range = AbsoluteRange.create(relativeRange.getFrom(), relativeRange.getTo());

            MessageFormat messageFormat = new MessageFormat("{0}: /.*{1}/", Locale.getDefault());
            String query = messageFormat.format(new Object[]{alertIdentifierFieldName, suffixID});
            LOGGER.debug("Alert Query: {}", query);

            // Add stream filter
            String filter = "streams:" + aggregationStream;
            LOGGER.debug("Alert filter: {}", filter);

            // Execute query
            SearchResult result = this.searches.search(query, filter, range, 1, 0, new Sorting(Message.FIELD_TIMESTAMP, Sorting.Direction.DESC));

            if (result != null && !result.getResults().isEmpty()) {
                LOGGER.debug(result.getResults().size() + " Alert found");
                // return the first matching alert
                return result.getResults().get(0).getMessage().getField(alertIdentifierFieldName).toString();
            }
        } catch (InvalidRangeParametersException e) {
            LOGGER.error("[getAggregationAlertID] - ERROR!", e);
        }
        return null;
    }
}
