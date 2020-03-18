import React from 'react';
import PropTypes from 'prop-types';
import { Well } from 'components/graylog';

//import CommonNotificationSummary from 'components/event-notifications';

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

        <React.Fragment>
          <tr>
            <td>Alert Severity:</td>
            <td>{notification.config.severity.join(', ') || 'No severity for this notification.'}</td>
          </tr>
          <tr>
            <td>Log Content:</td>
			  <Well bsSize="small" className={styles.bodyPreview}>
			    {notification.config.log_body || <em>Empty body</em>}
			  </Well>
          </tr>
        </React.Fragment>
       
    );
  }
}

export default LoggingAlertSummary;
