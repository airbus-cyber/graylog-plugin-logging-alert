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
