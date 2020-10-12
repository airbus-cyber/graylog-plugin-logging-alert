import React from 'react';

import createReactClass from 'create-react-class';
import { Spinner } from 'components/common';
import LoggingAlertForm from './LoggingAlertForm';
import connect from 'stores/connect';
import { FieldTypesStore } from 'views/stores/FieldTypesStore';

const LoggingAlertFormContainer = createReactClass({

    render() {
        const { fieldTypes, ...otherProps } = this.props;
        const isLoading = typeof fieldTypes.all !== 'object';

        if (isLoading) {
            return <Spinner text="Loading Logging Alert Information..." />;
        }

        return <LoggingAlertForm allFieldTypes={fieldTypes.all.toJS()} {...otherProps} />;
    }
})

export default connect(LoggingAlertFormContainer, {
    fieldTypes: FieldTypesStore,
});