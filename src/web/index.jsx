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
// sources of inspiration for this code:
// * components/maps/configurations/index.ts
// * graylog-plugin-integrations, src/web/index.jsx (see https://github.com/Graylog2/graylog-plugin-integrations/pull/964)
// * https://github.com/Graylog2/graylog-plugin-threatintel, index.jsx, now threatintel/bindings.jsx
// * https://github.com/Graylog2/graylog-plugin-aws, index.jsx
// * https://github.com/Graylog2/graylog-plugin-collector, index.jsx
import './webpack-entry';
import packageJson from '../../package.json';
import { PluginManifest, PluginStore } from 'graylog-web-plugin/plugin';
import LoggingAlertConfig from 'components/LoggingAlertConfig';
import LoggingAlertFormContainer from 'components/event-notifications/LoggingAlertFormContainer';
import LoggingAlertSummary from 'components/event-notifications/LoggingAlertSummary';
import LoggingAlertNotificationDetails from 'components/event-notifications/LoggingAlertNotificationDetails';
export { DEFAULT_BODY_TEMPLATE } from 'components/LoggingAlertConfig';

const metadata = {
  name: packageJson.name
};

PluginStore.register(new PluginManifest(metadata, {
  systemConfigurations: [
    {
      component: LoggingAlertConfig,
      displayName: 'Logging Alert',
      configType: 'com.airbus_cyber_security.graylog.events.config.LoggingAlertConfig'
    },
  ],
  eventNotificationTypes: [
    {
      type: 'logging-alert-notification',
      displayName: 'Logging Alert Notification',
      formComponent: LoggingAlertFormContainer,
      summaryComponent: LoggingAlertSummary,
      detailsComponent: LoggingAlertNotificationDetails
    }
  ],
}));
