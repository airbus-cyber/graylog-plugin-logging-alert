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