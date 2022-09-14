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
 package org.graylog.events.search;

import org.graylog.events.processor.EventProcessorException;
import org.graylog.events.search.MoreSearch;
import org.graylog.plugins.views.search.Parameter;
import org.graylog.plugins.views.search.elasticsearch.QueryStringDecorators;
import org.graylog2.indexer.ranges.IndexRangeService;
import org.graylog2.plugin.indexer.searches.timeranges.InvalidRangeParametersException;
import org.graylog2.plugin.indexer.searches.timeranges.RelativeRange;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;
import org.graylog2.streams.StreamService;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.HashSet;
import java.util.Set;


public class MoreSearchTest {

    private MoreSearch subject;

    @Before
    public void setup() {
        StreamService streamService = Mockito.mock(StreamService.class);
        IndexRangeService indexRangeService = Mockito.mock(IndexRangeService.class);
        QueryStringDecorators esQueryDecorators = Mockito.mock(QueryStringDecorators.class);
        MoreSearchAdapter moreSearchAdapter = Mockito.mock(MoreSearchAdapter.class);
        this.subject = new MoreSearch(streamService, indexRangeService, esQueryDecorators, moreSearchAdapter);
    }

    @Test
    public void scrollQueryShouldNotFail() throws InvalidRangeParametersException, EventProcessorException {
        String query = "x: \"hello\"world\"";
        Set<String> streams = new HashSet<>();
        Set<Parameter> parameters = new HashSet<>();
        TimeRange timeRange = RelativeRange.create(10);
        MoreSearch.ScrollCallback callback = (messages, continueScrolling) -> {};
        this.subject.scrollQuery(query, streams, parameters, timeRange, 1, callback);
    }
}
