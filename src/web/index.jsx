import packageJson from '../../package.json';
import { PluginManifest, PluginStore } from 'graylog-web-plugin/plugin';
import LoggingAlertConfig from 'components/LoggingAlertConfig';
import LoggingAlertForm from 'components/event-notifications/LoggingAlertForm';
import LoggingAlertSummary from 'components/event-notifications/LoggingAlertSummary';

PluginStore.register(new PluginManifest(packageJson, {
  systemConfigurations: [
    {
      component: LoggingAlertConfig,
      configType: 'com.airbus_cyber_security.graylog.config.LoggingAlertConfig',
    },
  ],
  eventNotificationTypes: [
    {
      type: 'logging-alert-notification',
      displayName: 'Logging Alert Notification',
      formComponent: LoggingAlertForm,
      summaryComponent: LoggingAlertSummary,
      defaultConfig: LoggingAlertForm.defaultConfig,
    }
  ],
}));
