import React from 'react';
import PropTypes from 'prop-types';

import { Spinner } from 'components/common';

import LoggingAlertForm from './LoggingAlertForm';
import StoreProvider from 'injection/StoreProvider';

const FieldsStore = StoreProvider.getStore('Fields');

class LoggingAlertFormContainer extends React.Component {
    static propTypes = {
        config: PropTypes.object.isRequired,
        validation: PropTypes.object.isRequired,
        onChange: PropTypes.func.isRequired,
    };

    state = {
        fields: [],
    };

    componentDidMount() {
        this.loadSplitFields();
    }

    loadSplitFields = () => {
        FieldsStore.loadFields().then((fields) => {
            //add value to list fields if not present
            //if (config.separator && config.separator !== '' && fields.indexOf(config.separator) < 0) {
                //fields.push(config.separator);
            //}
            this.setState({fields: fields});
        });
    };

    render() {
        const { fields } = this.state;

        if (!fields) {
            return <p><Spinner text="Loading Notification information..." /></p>;
        }
        return <LoggingAlertForm {...this.props} fields={fields} />;
    }
}
export default LoggingAlertFormContainer;