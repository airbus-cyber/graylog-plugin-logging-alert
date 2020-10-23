/*
 * graylog-plugin-logging-alert Source Code
 * Copyright (C) 2018-2020 - Airbus CyberSecurity (SAS) - All rights reserved
 *
 * This file is part of the graylog-plugin-logging-alert GPL Source Code.
 *
 * graylog-plugin-logging-alert Source Code is free software:
 * you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this code.  If not, see <http://www.gnu.org/licenses/>.
 */

import React from 'react';
import PropTypes from 'prop-types';

import { Spinner } from 'components/common';
import LoggingAlertForm from './LoggingAlertForm';
import connect from 'stores/connect';
import { FieldTypesStore } from 'views/stores/FieldTypesStore';

class LoggingAlertFormContainer extends React.Component {
    static propTypes = {
        config: PropTypes.object.isRequired,
        validation: PropTypes.object.isRequired,
        onChange: PropTypes.func.isRequired,
        fieldTypes: PropTypes.object.isRequired,
    };

    render() {
        const { fieldTypes, ...otherProps } = this.props;
        const isLoading = typeof fieldTypes.all !== 'object';

        if (isLoading) {
            return <Spinner text="Loading Logging Alert Information..." />;
        }

        return <LoggingAlertForm allFieldTypes={fieldTypes.all.toJS()} {...otherProps} />;
    }
};

export default connect(LoggingAlertFormContainer, {
    fieldTypes: FieldTypesStore,
});