import packageJson from '../../package.json';
import { PluginManifest, PluginStore } from 'graylog-web-plugin/plugin';
import LoggingAlertConfig from 'components/LoggingAlertConfig';

PluginStore.register(new PluginManifest(packageJson, {
  systemConfigurations: [
    {
      component: LoggingAlertConfig,
      configType: 'com.airbus_cyber_security.graylog.config.LoggingAlertConfig',
    },
  ],
}));
