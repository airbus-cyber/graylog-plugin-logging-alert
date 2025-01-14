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

// sources of inspiration for this code
// * components/event-definitions/event-definition-form/EventDefinitionSummary.tsx
// * components/event-definitions/event-definition-types/FilterAggregationSummary.jsx

import * as React from 'react';
import PropTypes from 'prop-types';

import { ReadOnlyFormGroup } from 'components/common';
import { Well } from 'components/bootstrap';

import styles from './LoggingAlertSummary.css';


const LoggingAlertNotificationDetails = ({ notification }) => {
    return (
        <>
            <ReadOnlyFormGroup label="Log Content"
                               value={(
                                   <Well bsSize="small" className={styles.bodyPreview}>
                                       {notification.config.log_body}
                                   </Well>
                               )}
            />
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
