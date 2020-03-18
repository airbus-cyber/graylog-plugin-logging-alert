package com.airbus_cyber_security.graylog;

import org.graylog.events.notifications.NotificationDto;
import org.graylog2.plugin.rest.ValidationResult;
import org.junit.Assert;
import org.junit.Test;

import com.airbus_cyber_security.graylog.config.LoggingAlertConfig;
import com.airbus_cyber_security.graylog.config.SeverityType;

public class LoggingAlertNotificationTest {

	private NotificationDto getLoggingAlertNotification() {
		return NotificationDto.builder()
				.title("")
				.description("")
				.config(LoggingAlertConfig.Builder.create()
						.severity(SeverityType.LOW)
						.separator("")
						.logBody("")
						.aggregationStream("")
						.aggregationTime(0)
						.limitOverflow(0)
						.fieldAlertId("")
						.alertTag("")
						.overflowTag("")
						.build())
				.build();
	}
	
	@Test
	public void testValidateWithEmptyConfig() {
		final NotificationDto invalidNotification = getLoggingAlertNotification();
		final ValidationResult validationResult = invalidNotification.validate();
		Assert.assertTrue(validationResult.failed());
	}
}
