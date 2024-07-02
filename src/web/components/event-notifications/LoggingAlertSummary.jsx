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
import React from 'react';
import PropTypes from 'prop-types';
import { Well } from 'components/bootstrap';

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
                <td>Single Notification:</td>
                <td>{notification.config.single_notification? 'true' : 'false'}</td>
              </tr>
            </React.Fragment>
        </CommonNotificationSummary>
    );
  }
}

export default LoggingAlertSummary;
