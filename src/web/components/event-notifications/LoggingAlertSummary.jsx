import React from 'react';
import PropTypes from 'prop-types';
import { Well } from 'components/graylog';

import CommonNotificationSummary from "./CommonNotificationSummary";
import styles from './LoggingAlertSummary.css';

class LoggingAlertSummary extends React.Component {
  static propTypes = {
    type: PropTypes.string.isRequired,
    notification: PropTypes.object,
    definitionNotification: PropTypes.object.isRequired,
  };

  static defaultProps = {
    notification: {},
  };

  render() {
    const { notification } = this.props;
    return (
        <CommonNotificationSummary {...this.props}>
            <React.Fragment>
              <tr>
                <td>Alert Severity:</td>
                <td>{notification.config.severity || 'No severity for this notification.'}</td>
              </tr>
              <tr>
                <td>Log Content:</td>
                  <Well bsSize="small" className={styles.bodyPreview}>
                    {notification.config.log_body || <em>Empty body</em>}
                  </Well>
              </tr>
              <tr>
                <td>Split Fields:</td>
                <td>{notification.config.split_fields.join(', ') || 'No split fields for this notification.'}</td>
              </tr>
              <tr>
                <td>Aggregation Time Range:</td>
                <td>{notification.config.aggregation_time}</td>
              </tr>
              <tr>
                <td>Alert Tag:</td>
                <td>{notification.config.alert_tag}</td>
              </tr>
                <tr>
                    <td>Single Notification</td>
                    <td>{notification.config.single_notification? 'true' : 'false'}</td>
                </tr>
                <tr>
                    <td>Comment:</td>
                    <td>{notification.config.comment}</td>
                </tr>
            </React.Fragment>
        </CommonNotificationSummary>
    );
  }
}

export default LoggingAlertSummary;
