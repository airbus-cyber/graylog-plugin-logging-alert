/*
 * graylog-plugin-logging-alert Source Code
 * Copyright (C) 2018-2020 - Airbus CyberSecurity (SAS) - All rights reserved
 *
 * This file is part of the graylog-plugin-logging-alert GPL Source Code.
 *
 * graylog-plugin-logging-alert Source Code is free software:
 * you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this code.  If not, see <http://www.gnu.org/licenses/>.
 */

import 'webpack-entry';
import packageJson from '../../package.json';
import { PluginManifest, PluginStore } from 'graylog-web-plugin/plugin';
import LoggingAlertConfig from 'components/LoggingAlertConfig';
import LoggingAlertFormContainer from 'components/event-notifications/LoggingAlertFormContainer';
import LoggingAlertSummary from 'components/event-notifications/LoggingAlertSummary';
export {DEFAULT_BODY_TEMPLATE} from 'components/LoggingAlertConfig';

PluginStore.register(new PluginManifest(packageJson, {
  systemConfigurations: [
    {
      component: LoggingAlertConfig,
      configType: 'com.airbus_cyber_security.graylog.events.config.LoggingAlertConfig',
    },
  ],
  eventNotificationTypes: [
    {
      type: 'logging-alert-notification',
      displayName: 'Logging Alert Notification',
      formComponent: LoggingAlertFormContainer,
      summaryComponent: LoggingAlertSummary,
    }
  ],
}));
