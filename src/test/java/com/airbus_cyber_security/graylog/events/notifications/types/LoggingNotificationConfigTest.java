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
package com.airbus_cyber_security.graylog;

import com.airbus_cyber_security.graylog.events.config.SeverityType;
import com.airbus_cyber_security.graylog.events.notifications.types.LoggingNotificationConfig;
import org.graylog.events.notifications.*;
import org.graylog2.plugin.rest.ValidationResult;
import org.junit.*;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

public class LoggingNotificationConfigTest {

    @Rule
    public final MockitoRule mockitoRule = MockitoJUnit.rule();

    private NotificationDto getEmptyLoggingAlertNotification() {
        return NotificationDto.builder()
                .title("")
                .description("")
                .config(LoggingNotificationConfig.Builder.create()
                        .severity(SeverityType.LOW)
                        .splitFields(new HashSet<>())
                        .logBody("")
                        .aggregationTime(0)
                        .alertTag("")
                        .build())
                .build();
    }

    private NotificationDto getLoggingAlertNotification() {
        return NotificationDto.builder()
                .title("Logging Alert Title")
                .description("Logging alert")
                .config(LoggingNotificationConfig.Builder.create()
                        .severity(SeverityType.LOW)
                        .splitFields(new HashSet<>())
                        .logBody("body test ")
                        .aggregationTime(0)
                        .alertTag("alert_tag_test")
                        .build())
                .build();
    }

    @Test
    public void testValidateWithEmptyConfig() {
        final NotificationDto invalidNotification = getEmptyLoggingAlertNotification();
        final ValidationResult validationResult = invalidNotification.validate();
        Assert.assertTrue(validationResult.failed());
    }

    @Test
    public void testValidateLoggingAlertNotification() {
        final NotificationDto validNotification = getLoggingAlertNotification();

        final ValidationResult validationResult = validNotification.validate();
        assertThat(validationResult.failed()).isFalse();
        assertThat(validationResult.getErrors().size()).isEqualTo(0);
    }
}
