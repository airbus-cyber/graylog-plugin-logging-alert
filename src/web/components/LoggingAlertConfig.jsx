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
import PropTypes from 'prop-types';
import React from 'react';
import createReactClass from 'create-react-class';
import { BootstrapModalForm, Button, Input } from 'components/bootstrap';
import IfPermitted from 'components/common/IfPermitted';
import Select from 'components/common/Select';
import Spinner from 'components/common/Spinner';
import ObjectUtils from 'util/ObjectUtils';
import naturalSort from 'javascript-natural-sort';
// TODO: should it be done like this with the singleton import (like in pages/ShowMessagePage.tsx), or like in views/components/SearchBar with a connect? => coding recommandation. Seems easier with a singleton...
import StreamsStore from 'stores/streams/StreamsStore';

export const DEFAULT_BODY_TEMPLATE = "type: alert"  + "\n" +
    "id: ${logging_alert.id}"  + "\n" +
    "severity: ${logging_alert.severity}" + "\n" +
    "app: graylog"  + "\n" +
    "subject: ${event_definition_title}" + "\n" +
    "body: ${event_definition_description}" + "\n" +
    "${if backlog && backlog[0]} src: ${backlog[0].fields.src_ip}" + "\n" +
    "src_category: ${backlog[0].fields.src_category}" + "\n" +
    "dest: ${backlog[0].fields.dest_ip}" + "\n" +
    "dest_category: ${backlog[0].fields.dest_category}" + "\n" +
    "${end}";

const LoggingAlertConfig = createReactClass({
    displayName: 'LoggingAlertConfig',

    propTypes: {
        config: PropTypes.object,
        updateConfig: PropTypes.func.isRequired,
    },

    getDefaultProps() {
        return {
            config: {
                field_alert_id: 'id',
                severity: 'LOW',
                separator: ' | ',
                log_body: DEFAULT_BODY_TEMPLATE,
                alert_tag: 'LoggingAlert',
                overflow_tag: 'LoggingOverflow',
            },
        };
    },

    getInitialState() {
        return {
            config: ObjectUtils.clone(this.props.config),
        };
    },

    // TODO is this still working? Remove?
    componentDidUpdate(newProps) {
        //this.setState({ config: ObjectUtils.clone(newProps.config) });
    },

    componentDidMount() {
        StreamsStore.listStreams().then((streams) => {
            this.setState({ streams: streams });
        });
    },

    _updateConfigField(field, value) {
        const update = ObjectUtils.clone(this.state.config);
        update[field] = value;
        this.setState({ config: update });
    },

    _onCheckboxClick(field, ref) {
        return () => {
            this._updateConfigField(field, this.refs[ref].getChecked());
        };
    },

    _onSelect(field) {
        return (selection) => {
            this._updateConfigField(field, selection);
        };
    },

    _onUpdate(field) {
        return e => {
            this._updateConfigField(field, e.target.value);
        };
    },

    _openModal() {
        this.refs.loggingAlertConfigModal.open();
    },

    _closeModal() {
        this.refs.loggingAlertConfigModal.close();
    },

    _resetConfig() {
        // Reset to initial state when the modal is closed without saving.
        this.setState(this.getInitialState());
    },

    _saveConfig() {
        this.props.updateConfig(this.state.config).then(() => {
            this._closeModal();
        });
    },

    _availableSeverityTypes() {
        return [
            {value: 'HIGH', label: 'High'},
            {value: 'MEDIUM', label: 'Medium'},
            {value: 'LOW', label: 'Low'},
            {value: 'INFO', label: 'Info'},
        ];
    },

    _activeSeverityType(type) {
        return this._availableSeverityTypes().filter((t) => t.value === type)[0].label;
    },

    _onSeverityTypeSelect(id) {
        const update = ObjectUtils.clone(this.state.config);
        update['severity'] = id;
        this.setState({ config: update });
    },

    _onAggregationStreamSelect(id) {
        const update = ObjectUtils.clone(this.state.config);
        update['aggregation_stream'] = id;
        this.setState({ config: update });
    },

    _formatOption(key, value) {
        return { value: value, label: key };
    },

    render() {
        if (!this.state.streams) {
            return <Spinner />;
        }

        const formattedStreams = this.state.streams
            .map(stream => this._formatOption(stream.title, stream.id))
            .sort((s1, s2) => naturalSort(s1.label.toLowerCase(), s2.label.toLowerCase()));

        return (
            <div>
                <h3>Logging Alert Notification Configuration</h3>

                <p>
                    Base configuration for all plugins the Logging Alert Notification module is providing. Note
                    that some parameters will be stored in MongoDB without encryption.
                    Graylog users with required permissions will be able to read them in
                    the configuration dialog on this page.
                </p>
                <dl className="deflist">
                    <dt>Alert Severity: </dt>
                    <dd>
                        {this._activeSeverityType(this.state.config.severity)}
                    </dd>
                </dl>
                <dl className="deflist">
                    <dt>Log Content: </dt>
                    <dd>
                        {this.state.config.log_body ? this.state.config.log_body : '[not set]'}
                    </dd>
                </dl>
                <dl className="deflist">
                    <dt>Line Break Substitution: </dt>
                    <dd>
                        {this.state.config.separator ? this.state.config.separator : '[not set]'}
                    </dd>
                </dl>
                <dl className="deflist">
                    <dt>Aggregation Time Range: </dt>
                    <dd>
                        {this.state.config.aggregation_time ? this.state.config.aggregation_time : '[not set]'}
                    </dd>
                </dl>
                <dl className="deflist">
                    <dt>Alerts Stream: </dt>
                    <dd>
                        {this.state.config.aggregation_stream ? this.state.config.aggregation_stream : '[not set]'}
                    </dd>
                </dl>
                <dl className="deflist">
                    <dt>Alert ID Field: </dt>
                    <dd>
                        {this.state.config.field_alert_id ? this.state.config.field_alert_id : '[not set]'}
                    </dd>
                </dl>
                <dl className="deflist">
                    <dt>Overflow Limit: </dt>
                    <dd>
                        {this.state.config.limit_overflow ? this.state.config.limit_overflow : '[not set]'}
                    </dd>
                </dl>
                <dl className="deflist">
                    <dt>Alert Tag: </dt>
                    <dd>
                        {this.state.config.alert_tag ? this.state.config.alert_tag : '[not set]'}
                    </dd>
                </dl>
                <dl className="deflist">
                    <dt>Overflow Tag: </dt>
                    <dd>
                        {this.state.config.overflow_tag ? this.state.config.overflow_tag : '[not set]'}
                    </dd>
                </dl>

                <IfPermitted permissions="clusterconfigentry:edit">
                    <Button bsStyle="info" bsSize="xs" onClick={this._openModal}>
                        Configure
                    </Button>
                </IfPermitted>

                <BootstrapModalForm
                    ref="loggingAlertConfigModal"
                    title="Update Logging Alert Notification Configuration"
                    onSubmitForm={this._saveConfig}
                    onModalClose={this._resetConfig}
                    submitButtonText="Save">
                    <fieldset>
                        <Input
                            id="severity"
                            label="Default Alert Severity"
                            help="The default severity of logged alerts when adding a new notification"
                            name="severity">
                            <Select placeholder="Select the severity"
                                    required
                                    options={this._availableSeverityTypes()}
                                    matchProp="value"
                                    value={this.state.config.severity}
                                    onChange={this._onSeverityTypeSelect}
                            />
                        </Input>
                        <Input
                            id="log-body"
                            type="textarea"
                            label="Default Log Content"
                            help="The default template to generate the log content from when adding a new notification"
                            name="log_body"
                            value={this.state.config.log_body}
                            onChange={this._onUpdate('log_body')}
                            rows={10}
                        />
                        <Input
                            id="separator"
                            type="text"
                            label="Line Break Substitution"
                            help="The separator to insert between the fields of the log content when adding a new notification"
                            name="separator"
                            value={this.state.config.separator}
                            onChange={this._onUpdate('separator')}
                        />
                        <Input
                            id="aggregation-time"
                            type="number"
                            label="Default Aggregation Time Range"
                            name="aggregation_time"
                            help="The default number of minutes to aggregate alerts by logging alerts with the same alert id when adding a new notification"
                            value={this.state.config.aggregation_time}
                            onChange={this._onUpdate('aggregation_time')}
                        />
                        <Input  id="aggregation-stream"
                                label="Alerts Stream"
                                help="Stream receiving the logged alerts that allows to aggregate alerts"
                                name="aggregation_stream">
                            <Select placeholder="Select the stream for the aggregation"
                                    options={formattedStreams}
                                    matchProp="value"
                                    value={this.state.config.aggregation_stream}
                                    onChange={this._onAggregationStreamSelect} />
                        </Input>
                        <Input
                            id="field_alert_id"
                            type="text"
                            label="Alert ID Field"
                            name="field_alert_id"
                            help="Field that should be checked to get the alert id in the messages of the Alerts Stream"
                            value={this.state.config.field_alert_id}
                            onChange={this._onUpdate('field_alert_id')}
                        />
                        <Input
                            id="limit-overflow"
                            type="number"
                            label="Overflow Limit"
                            name="limit_overflow"
                            help="Number of generated logs per alert from which they are tagged as overflow"
                            value={this.state.config.limit_overflow}
                            onChange={this._onUpdate('limit_overflow')}
                        />
                        <Input
                            id="alert_tag"
                            type="text"
                            label="Alert Tag"
                            name="alert_tag"
                            help="The tag of the generated logs"
                            value={this.state.config.alert_tag}
                            onChange={this._onUpdate('alert_tag')}
                        />
                        <Input
                            id="overflow_tag"
                            type="text"
                            label="Overflow Tag"
                            name="overflow_tag"
                            help="The tag of the generated logs when the number of generated logs per alert is higher than the overflow limit"
                            value={this.state.config.overflow_tag}
                            onChange={this._onUpdate('overflow_tag')}
                        />

                    </fieldset>
                </BootstrapModalForm>
            </div>
        );
    },
});

export default LoggingAlertConfig;

