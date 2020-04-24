import React from 'react';
import PropTypes from 'prop-types';
import Reflux from 'reflux';
import createReactClass from 'create-react-class';

import { Spinner } from 'components/common';

import LoggingAlertForm from './LoggingAlertForm';
import StoreProvider from 'injection/StoreProvider';

const FieldsStore = StoreProvider.getStore('Fields');


const LoggingAlertFormContainer = createReactClass({
    getInitialState() {
        return {
            fields: [],
        };
    },

    componentDidMount() {
        this.loadSplitFields();
    },

    loadSplitFields() {
        FieldsStore.loadFields().then((fields) => {
            this.setState({fields: fields});
        });
    },

    render() {
        const { fields } = this.state;

        if (!fields) {
            return <p><Spinner text="Loading Notification information..." /></p>;
        }
        return <LoggingAlertForm {...this.props} fields={fields} />;
    }
})
export default LoggingAlertFormContainer;