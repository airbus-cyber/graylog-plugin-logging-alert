import * as React from 'react';
import PropTypes from 'prop-types';

import { ReadOnlyFormGroup } from 'components/common';
import { Well } from 'components/graylog';

import styles from './LoggingAlertSummary.css';


const LoggingAlertNotificationDetails = ({ notification }) => {
    return (
        <>
            <ReadOnlyFormGroup label="Alert Severity" value={notification.config.severity} />
            <ReadOnlyFormGroup label="Log Content"
                               value={(
                                   <Well bsSize="small" className={styles.bodyPreview}>
                                       {notification.config.log_body}
                                   </Well>
                               )}
            />
            <ReadOnlyFormGroup label="Split Fields" value={notification.config.split_fields} />
            <ReadOnlyFormGroup label="Aggregation Time Range" value={notification.config.aggregation_time} />
            <ReadOnlyFormGroup label="Alert Tag" value={notification.config.alert_tag} />
            <ReadOnlyFormGroup label="Single Notification" value={notification.config.single_notification} />
        </>
    );
};

LoggingAlertNotificationDetails.propTypes = {
    notification: PropTypes.object.isRequired,
};

export default LoggingAlertNotificationDetails;