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
import PropTypes from 'prop-types';

import { Spinner } from 'components/common';
import LoggingAlertForm from './LoggingAlertForm';
import useFieldTypes from 'views/logic/fieldtypes/useFieldTypes';
import { ALL_MESSAGES_TIMERANGE } from 'views/Constants';

type Props = {
    config: {},
    validation: {},
    onChange: () => void,
}

const LoggingAlertFormContainer = (props: Props) => {
    const { data: fieldTypes } = useFieldTypes([], ALL_MESSAGES_TIMERANGE);
    const isLoading = !fieldTypes;

    if (isLoading) {
        return <Spinner text="Loading Logging Alert information..." />;
    }
    // TODO add a test when allFieldTypes is not passed down
    return <LoggingAlertForm allFieldTypes={fieldTypes} {...props} />;
}

LoggingAlertFormContainer.propTypes = {
    config: PropTypes.object.isRequired,
    validation: PropTypes.object.isRequired,
    onChange: PropTypes.func.isRequired,
}

export default LoggingAlertFormContainer;
