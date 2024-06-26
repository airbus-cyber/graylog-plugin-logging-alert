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
// * components/common/URLWhiteListFormModal.tsx
// * components/maps/configurations/GeoIpResolverConfig.tsx
// * views/components/messagelist/MessageTableEntry.tsx
// * pages/ShowMessagePage.tsx
// * components/pipelines/ProcessingTimelineComponent.tsx (with useEffect for StreamsStore
// * threatintel/components/ThreatIntelPluginConfig.jsx
import React, { useState } from 'react';
import { useStore } from 'stores/connect';
import { StreamsStore } from 'views/stores/StreamsStore';
import { defaultCompare } from 'logic/DefaultCompare'

import { BootstrapModalForm, Button, Input } from 'components/bootstrap';
import IfPermitted from 'components/common/IfPermitted';
import Select from 'components/common/Select';
import Spinner from 'components/common/Spinner';

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
    separator: ' | ',
    log_body: DEFAULT_BODY_TEMPLATE,
    alert_tag: 'LoggingAlert',
    overflow_tag: 'LoggingOverflow',
};

const _formatOption = (key, value) => {
    return { value: value, label: key };
};

const _displayOptionalConfigurationValue = (value) => {
    if (!value) {
        return '[not set]';
    }
    return value;
};

const LoggingAlertConfig = ({ config = DEFAULT_CONFIG, updateConfig }) => {
    const [nextConfiguration, setNextConfiguration] = useState(config);
    const [showModal, setShowModal] = useState(false);
    const { streams: streamList = [] } = useStore(StreamsStore);

    const _openModal = () => {
        setShowModal(true);
    };

    const _closeModal = () => {
        setShowModal(false);
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
        // note: this is necessary to cancel current configuration changes
        //       scenario: open the configuration popup, change a field value, cancel, reopen the configuration popup
        //                 the field value should be back to what it was before its change
        setNextConfiguration(config);
        _closeModal();
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

    const _onAggregationStreamSelect = (value) => {
        _updateConfigurationField('aggregation_stream', value);
    };

    if (!streamList) {
        return <Spinner />;
    }

    const formattedStreams = streamList
        .map(stream => _formatOption(stream.title, stream.id))
        .sort((s1, s2) => defaultCompare(s1.label.toLowerCase(), s2.label.toLowerCase()));

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
                <dt>Log Content: </dt>
                <dd>
                    {_displayOptionalConfigurationValue(config.log_body)}
                </dd>
            </dl>
            <dl className="deflist">
                <dt>Line Break Substitution: </dt>
                <dd>
                    {_displayOptionalConfigurationValue(config.separator)}
                </dd>
            </dl>
            <dl className="deflist">
                <dt>Aggregation Time Range: </dt>
                <dd>
                    {_displayOptionalConfigurationValue(config.aggregation_time)}
                </dd>
            </dl>
            <dl className="deflist">
                <dt>Alerts Stream: </dt>
                <dd>
                    {_displayOptionalConfigurationValue(config.aggregation_stream)}
                </dd>
            </dl>
            <dl className="deflist">
                <dt>Alert ID Field: </dt>
                <dd>
                    {_displayOptionalConfigurationValue(config.field_alert_id)}
                </dd>
            </dl>
            <dl className="deflist">
                <dt>Overflow Limit: </dt>
                <dd>
                    {_displayOptionalConfigurationValue(config.limit_overflow)}
                </dd>
            </dl>
            <dl className="deflist">
                <dt>Alert Tag: </dt>
                <dd>
                    {_displayOptionalConfigurationValue(config.alert_tag)}
                </dd>
            </dl>
            <dl className="deflist">
                <dt>Overflow Tag: </dt>
                <dd>
                    {_displayOptionalConfigurationValue(config.overflow_tag)}
                </dd>
            </dl>

            <IfPermitted permissions="clusterconfigentry:edit">
                <Button bsStyle="info" bsSize="xs" onClick={_openModal}>
                    Edit configuration
                </Button>
            </IfPermitted>

            <BootstrapModalForm
                show={showModal}
                title="Update Logging Alert Notification Configuration"
                onSubmitForm={_saveConfiguration}
                onCancel={_resetConfiguration}
                submitButtonText="Save">
                <fieldset>
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
                                options={formattedStreams}
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
