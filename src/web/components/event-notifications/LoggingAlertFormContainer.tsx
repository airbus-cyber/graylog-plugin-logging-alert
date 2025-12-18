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

// sources of inspiration for this code: components/event-definitions/event-definition-form/field-value-providers/LookupTableFieldValueProviderFormContainer.tsx
import React from 'react';

import type { EventNotificationTypes } from 'components/event-notifications/types';
import LoggingAlertForm from './LoggingAlertForm';
type Props = React.ComponentProps<EventNotificationTypes['formComponent']>;

const LoggingAlertFormContainer = (props: Props) => {
    return <LoggingAlertForm {...props} />;
}

export default LoggingAlertFormContainer;
