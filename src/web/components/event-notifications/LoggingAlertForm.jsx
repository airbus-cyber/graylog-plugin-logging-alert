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
import React from 'react';
import PropTypes from 'prop-types';

import { ControlLabel, FormGroup, HelpBlock } from 'components/bootstrap';
import lodash from 'lodash';
import { Select, MultiSelect } from 'components/common';
// TODO this works, but should rather load the SourceCodeEditor from the index (it will then use lazy-loading)
//      => import { SourceCodeEditor } from 'components/common';
//      however, it doesn't work, since the graylog server does not serve the js file corresponding to the SourceCodeEditor
import SourceCodeEditor from 'components/common/SourceCodeEditor';
import { Input } from 'components/bootstrap';
import FormsUtils from 'util/FormsUtils';
import { ConfigurationsActions, ConfigurationsStore } from 'stores/configurations/ConfigurationsStore';
import {DEFAULT_BODY_TEMPLATE} from '../LoggingAlertConfig'

import connect from 'stores/connect';

import { defaultCompare } from 'logic/DefaultCompare';

const LOGGING_ALERT_CONFIG = 'com.airbus_cyber_security.graylog.events.config.LoggingAlertConfig';


class LoggingAlertForm extends React.Component {
    // Memoize function to only format fields when they change. Use joined fieldNames as cache key.
    formatFields = lodash.memoize(
        (fieldTypes) => {
            return fieldTypes
                .sort((ftA, ftB) => defaultCompare(ftA.name, ftB.name))
                .map((fieldType) => {
                    return {
                        label: `${fieldType.name} – ${fieldType.value.type.type}`,
                        value: fieldType.name,
                    };
                }
            );
        },
        (fieldTypes) => fieldTypes.map((ft) => ft.name).join('-'),
    );

	static propTypes = {
        config: PropTypes.object.isRequired,
        validation: PropTypes.object.isRequired,
        onChange: PropTypes.func.isRequired,
  	    allFieldTypes: PropTypes.array.isRequired,
    };

    constructor(props) {
        super(props);
        this.state = {};
    }

	componentDidMount() {
        // TODO add a test when ConfigurationsActions is misstyped into ConfigurationActions
		ConfigurationsActions.list(LOGGING_ALERT_CONFIG);
	}
  
    propagateChange = (key, value) => {
	    const { config, onChange } = this.props;
	    const nextConfig = lodash.cloneDeep(config);
	    nextConfig[key] = value;
	    onChange(nextConfig);
    };

    handleChange = (event) => {
	    const { name } = event.target;
	    this.propagateChange(name, FormsUtils.getValueFromInput(event.target));
    };

    handleBodyTemplateChange = (nextValue) => {
	    this.propagateChange('log_body', nextValue);
    };

    handleFieldsChange = (key) => {
  	    return nextValue => {
  		    this.propagateChange(key, nextValue === '' ? [] : nextValue.split(','));
	    }
    };

    getAlertConfig = (configuration) => {
  	    if (configuration && configuration[LOGGING_ALERT_CONFIG]) {
		    if (this.props.config.log_body === undefined){
			    this.handleBodyTemplateChange(configuration[LOGGING_ALERT_CONFIG].log_body);
		    }
		    if (this.props.config.aggregation_time === undefined){
			    this.propagateChange('aggregation_time', configuration[LOGGING_ALERT_CONFIG].aggregation_time);
		    }
		    if (this.props.config.alert_tag === undefined){
			    this.propagateChange('alert_tag', configuration[LOGGING_ALERT_CONFIG].alert_tag);
		    }
  		    return configuration[LOGGING_ALERT_CONFIG];
	    } else {
  		    return {
			    log_body: DEFAULT_BODY_TEMPLATE,
			    alert_tag: 'LoggingAlert',
			    aggregation_time: 0,
			    single_notification: false,
		    }
	    }
    };
    
    render() {
        const { config, validation, allFieldTypes } = this.props;
        const formattedFields = this.formatFields(allFieldTypes);

        const alertConfig = this.getAlertConfig(this.props.configurationsStore.configuration);

        return (
            <React.Fragment>
                <FormGroup controlId="log_body" validationState={validation.errors.log_body ? 'error' : null}>
                    <ControlLabel>Body Template</ControlLabel>
                    <SourceCodeEditor id="log_body"
                        mode="text"
                        theme="light"
                        value={config.log_body? config.log_body : alertConfig.log_body}
                        onChange={this.handleBodyTemplateChange} />
                    <HelpBlock>
                        {lodash.get(validation, 'errors.log_body[0]', 'The template to generate the log content form')}
                    </HelpBlock>
                </FormGroup>

	            <ControlLabel>Aggregation Time Range <small className="text-muted">(Optional)</small></ControlLabel>
                <Input
                    id="aggregation_time"
                    type="number"
                    name="aggregation_time"
                    help="Aggregate alerts received in the given number of minutes. If some Group by Fields have been configured in the Event Definition they will also be used to aggregate alerts"
                    value={config.aggregation_time === undefined? alertConfig.aggregation_time : config.aggregation_time}
                    onChange={this.handleChange}
                />
	            <ControlLabel>Alert Tag <small className="text-muted">(Optional)</small></ControlLabel>
                <Input
                    id="alert_tag"
                    type="text"
                    name="alert_tag"
                    help="This tag is added at the begining of the generated logs"
                    value={config.alert_tag? config.alert_tag : alertConfig.alert_tag}
                    onChange={this.handleChange}
                />
	            <div>
                    <Input
                        id="single_notification"
                        type="checkbox"
                        name="single_notification"
                        checked={config.single_notification}
                        onChange={this.handleChange}
                        style={{position: 'absolute'}}
                    />
                        <label style={{padding: '10px 20px'}}>Single Message <small className='text-muted'>(Optional)</small></label>
                    <HelpBlock>
                      Check this box to send only one message by alert
                    </HelpBlock>
	            </div>
	        </React.Fragment>
        );
    }
}

// TODO rather than connect, should maybe use useStore (see graylog components/common/URLWhiteListFormModal.tsx)
export default connect(LoggingAlertForm, {
    configurationsStore: ConfigurationsStore
});
