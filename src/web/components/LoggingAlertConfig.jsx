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

// sources of inspiration for this code:
// * components/maps/configurations/GeoIpResolverConfig.tsx
import PropTypes from 'prop-types';
import React, { useState, useRef } from 'react';
import createReactClass from 'create-react-class';
// TODO use Modal instead of BootstrapModalForm??
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

const DEFAULT_CONFIG = {
    field_alert_id: 'id',
    severity: 'LOW',
    separator: ' | ',
    log_body: DEFAULT_BODY_TEMPLATE,
    alert_tag: 'LoggingAlert',
    overflow_tag: 'LoggingOverflow',
};

const AVAILABLE_SEVERITY_TYPES = [
    {value: 'HIGH', label: 'High'},
    {value: 'MEDIUM', label: 'Medium'},
    {value: 'LOW', label: 'Low'},
    {value: 'INFO', label: 'Info'},
];

const _displayActiveSeverityType = (type) => {
    return AVAILABLE_SEVERITY_TYPES.filter((t) => t.value === type)[0].label;
}

// TODO factor all [not set] with a function displayConfigurationValue()
const LoggingAlertConfig = ({ config = DEFAULT_CONFIG, updateConfig }) => {
    const [nextConfiguration, setNextConfiguration] = useState(config);

    // TODO try to avoid useRef (use Modal instead of BootsrapModalForm?)
    const configurationModal = useRef();

    const _openModal = () => {
        configurationModal.current.open()
    };

    const _closeModal = () => {
        configurationModal.current.close()
    };

/* TODO is this necessary?
    useEffect(() => {
        setNextConfiguration({ ...config });
    }, [config]);
*/

    const _saveConfiguration = () => {
        updateConfig(nextConfiguration).then(() => {
            _closeModal();
        })
    };

    const _resetConfiguration = () => {
        setNextConfiguration(config);
    };

    const _updateConfigurationField = (field, value) => {
        const newConfiguration = {...nextConfiguration};
        newConfiguration[field] = value;
        setNextConfiguration(newConfiguration);
    };

    const _onUpdate = (field) => {
        return e => {
            _updateConfigurationField(field, e.target.value);
        };
    };

    const _onSeverityTypeSelect = (value) => {
        _updateConfigurationField('severity', value);
    };

    const _onAggregationStreamSelect = (value) => {
        _updateConfigurationField('aggregation_stream', value);
    };

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
                    {_displayActiveSeverityType(config.severity)}
                </dd>
            </dl>
            <dl className="deflist">
                <dt>Log Content: </dt>
                <dd>
                    {config.log_body ? config.log_body : '[not set]'}
                </dd>
            </dl>
            <dl className="deflist">
                <dt>Line Break Substitution: </dt>
                <dd>
                    {config.separator ? config.separator : '[not set]'}
                </dd>
            </dl>
            <dl className="deflist">
                <dt>Aggregation Time Range: </dt>
                <dd>
                    {config.aggregation_time ? config.aggregation_time : '[not set]'}
                </dd>
            </dl>
            <dl className="deflist">
                <dt>Alerts Stream: </dt>
                <dd>
                    {config.aggregation_stream ? config.aggregation_stream : '[not set]'}
                </dd>
            </dl>
            <dl className="deflist">
                <dt>Alert ID Field: </dt>
                <dd>
                    {config.field_alert_id ? config.field_alert_id : '[not set]'}
                </dd>
            </dl>
            <dl className="deflist">
                <dt>Overflow Limit: </dt>
                <dd>
                    {config.limit_overflow ? config.limit_overflow : '[not set]'}
                </dd>
            </dl>
            <dl className="deflist">
                <dt>Alert Tag: </dt>
                <dd>
                    {config.alert_tag ? config.alert_tag : '[not set]'}
                </dd>
            </dl>
            <dl className="deflist">
                <dt>Overflow Tag: </dt>
                <dd>
                    {config.overflow_tag ? config.overflow_tag : '[not set]'}
                </dd>
            </dl>

            <IfPermitted permissions="clusterconfigentry:edit">
                <Button bsStyle="info" bsSize="xs" onClick={_openModal}>
                    Configure
                </Button>
            </IfPermitted>

            <BootstrapModalForm
                ref={configurationModal}
                title="Update Logging Alert Notification Configuration"
                onSubmitForm={_saveConfiguration}
                onModalClose={_resetConfiguration}
                submitButtonText="Save">
                <fieldset>
                    <Input
                        id="severity"
                        label="Default Alert Severity"
                        help="The default severity of logged alerts when adding a new notification"
                        name="severity">
                        <Select placeholder="Select the severity"
                                required
                                options={AVAILABLE_SEVERITY_TYPES}
                                matchProp="value"
                                value={nextConfiguration.severity}
                                onChange={_onSeverityTypeSelect}
                        />
                    </Input>
                    <Input
                        id="log-body"
                        type="textarea"
                        label="Default Log Content"
                        help="The default template to generate the log content from when adding a new notification"
                        name="log_body"
                        value={nextConfiguration.log_body}
                        onChange={_onUpdate('log_body')}
                        rows={10}
                    />
                    <Input
                        id="separator"
                        type="text"
                        label="Line Break Substitution"
                        help="The separator to insert between the fields of the log content when adding a new notification"
                        name="separator"
                        value={nextConfiguration.separator}
                        onChange={_onUpdate('separator')}
                    />
                    <Input
                        id="aggregation-time"
                        type="number"
                        label="Default Aggregation Time Range"
                        name="aggregation_time"
                        help="The default number of minutes to aggregate alerts by logging alerts with the same alert id when adding a new notification"
                        value={nextConfiguration.aggregation_time}
                        onChange={_onUpdate('aggregation_time')}
                    />
                    <Input  id="aggregation-stream"
                            label="Alerts Stream"
                            help="Stream receiving the logged alerts that allows to aggregate alerts"
                            name="aggregation_stream">
                        <Select placeholder="Select the stream for the aggregation"
                                options={[]/* TODO formattedStreams */}
                                matchProp="value"
                                value={nextConfiguration.aggregation_stream}
                                onChange={_onAggregationStreamSelect} />
                    </Input>
                    <Input
                        id="field_alert_id"
                        type="text"
                        label="Alert ID Field"
                        name="field_alert_id"
                        help="Field that should be checked to get the alert id in the messages of the Alerts Stream"
                        value={nextConfiguration.field_alert_id}
                        onChange={_onUpdate('field_alert_id')}
                    />
                    <Input
                        id="limit-overflow"
                        type="number"
                        label="Overflow Limit"
                        name="limit_overflow"
                        help="Number of generated logs per alert from which they are tagged as overflow"
                        value={nextConfiguration.limit_overflow}
                        onChange={_onUpdate('limit_overflow')}
                    />
                    <Input
                        id="alert_tag"
                        type="text"
                        label="Alert Tag"
                        name="alert_tag"
                        help="The tag of the generated logs"
                        value={nextConfiguration.alert_tag}
                        onChange={_onUpdate('alert_tag')}
                    />
                    <Input
                        id="overflow_tag"
                        type="text"
                        label="Overflow Tag"
                        name="overflow_tag"
                        help="The tag of the generated logs when the number of generated logs per alert is higher than the overflow limit"
                        value={nextConfiguration.overflow_tag}
                        onChange={_onUpdate('overflow_tag')}
                    />

                </fieldset>
            </BootstrapModalForm>
        </div>
    );
};

export default LoggingAlertConfig;
