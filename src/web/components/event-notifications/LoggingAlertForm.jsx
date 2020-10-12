import React from 'react';
import PropTypes from 'prop-types';

import { ControlLabel, FormGroup, HelpBlock } from 'components/graylog';
import lodash from 'lodash';
import naturalSort from 'javascript-natural-sort';
import { Select, MultiSelect } from 'components/common';
// TODO this works, but should rather load the SourceCodeEditor from the index (it will then use lazy-loading)
//      => import { SourceCodeEditor } from 'components/common';
//      however, it doesn't work, since the graylog server does not serve the js file corresponding to the SourceCodeEditor
import SourceCodeEditor from 'components/common/SourceCodeEditor';
import { Input } from 'components/bootstrap';
import FormsUtils from 'util/FormsUtils';
import Reflux from 'reflux';
import createReactClass from 'create-react-class';
import StoreProvider from 'injection/StoreProvider';
import ActionsProvider from 'injection/ActionsProvider';
import {DEFAULT_BODY_TEMPLATE} from '../LoggingAlertConfig'

const ConfigurationsStore = StoreProvider.getStore('Configurations');
const ConfigurationActions = ActionsProvider.getActions('Configuration');

import { defaultCompare } from 'views/logic/DefaultCompare';

const LoggingAlertForm = createReactClass({
	mixins: [Reflux.connect(ConfigurationsStore)],
	propTypes: {
    config: PropTypes.object.isRequired,
    validation: PropTypes.object.isRequired,
    onChange: PropTypes.func.isRequired,
  	allFieldTypes: PropTypes.array.isRequired,
  },

    formatFields(fieldTypes) {
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

	getInitialState() {
		return {
		};
	},

	LOGGING_ALERT_CONFIG: 'com.airbus_cyber_security.graylog.events.config.LoggingAlertConfig',

	componentDidMount() {
		ConfigurationActions.list(this.LOGGING_ALERT_CONFIG);
	},
  
  propagateChange(key, value) {
	const { config, onChange } = this.props;
	const nextConfig = lodash.cloneDeep(config);
	nextConfig[key] = value;
	onChange(nextConfig);
  },

  handleChange(event) {
	const { name } = event.target;
	this.propagateChange(name, FormsUtils.getValueFromInput(event.target));
  },

  handleSeverityChange(nextValue) {
  	this.propagateChange('severity', nextValue);
  },

  handleBodyTemplateChange(nextValue) {
	this.propagateChange('log_body', nextValue);
  },

  handleFieldsChange(key) {
  	return nextValue => {
  		this.propagateChange(key, nextValue === '' ? [] : nextValue.split(','));
	}
  },

  availableSeverityTypes() {
      return [
        {value: 'HIGH', label: 'High'},
        {value: 'MEDIUM', label: 'Medium'},
        {value: 'LOW', label: 'Low'}, 
        {value: 'INFO', label: 'Info'},  
      ];
  },
  
  _formatOption(key, value) {
  	return {value: value, label: key};
  },

    handleSplitFieldsChange(selected) {
        const nextValue = selected === '' ? [] : selected.split(',');
        this.propagateChange('split_fields', nextValue)
    },


  getAlertConfig() {
  	if (this.state.configuration && this.state.configuration[this.LOGGING_ALERT_CONFIG]) {
  		if(this.props.config.severity === undefined){
			this.handleSeverityChange(this.state.configuration[this.LOGGING_ALERT_CONFIG].severity);
		}
		if(this.props.config.log_body === undefined){
			this.handleBodyTemplateChange(this.state.configuration[this.LOGGING_ALERT_CONFIG].log_body);
		}
		if(this.props.config.aggregation_time === undefined){
			this.propagateChange('aggregation_time', this.state.configuration[this.LOGGING_ALERT_CONFIG].aggregation_time);
		}
		if(this.props.config.alert_tag === undefined){
			this.propagateChange('alert_tag', this.state.configuration[this.LOGGING_ALERT_CONFIG].alert_tag);
		}
  		return this.state.configuration[this.LOGGING_ALERT_CONFIG];
	}
  	else {
  		return {
			severity: 'LOW',
			log_body: DEFAULT_BODY_TEMPLATE,
			alert_tag: 'LoggingAlert',
			aggregation_time: 0,
			split_fields: [],
			single_notification: false,
		}
	}
  },
    
  render() {
    const { config, validation, allFieldTypes } = this.props;
    const formattedFields = this.formatFields(allFieldTypes);

    const alertConfig = this.getAlertConfig();

    return (
      <React.Fragment>
      <FormGroup controlId="severity"
	          validationState={validation.errors.severity ? 'error' : null}>
	     <ControlLabel>Alert Severity</ControlLabel>
	     <Select id="severity"
		     placeholder="Select Severity"
	         required
	         options={this.availableSeverityTypes()}
	         matchProp="value"
	         value={config.severity? config.severity : alertConfig.severity}
	         onChange={this.handleSeverityChange}
	     />
		 <HelpBlock>
		   {lodash.get(validation, 'errors.severity[0]', 'The severity of logged alerts')}
		 </HelpBlock>
	  </FormGroup>
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
        <FormGroup controlId="split_fields">
            <ControlLabel>Split Fields  <small className="text-muted">(Optional)</small></ControlLabel>
            <MultiSelect id="split_fields"
                         matchProp="label"
                         onChange={this.handleSplitFieldsChange}
                         options={formattedFields}
                         ignoreAccents={false}
                         value={lodash.defaultTo(config.split_fields, []).join(',')}
                         allowCreate />
            <HelpBlock>
                Fields that should be checked to split the alert according to each value by generating a different alert is for each value
            </HelpBlock>
        </FormGroup>

	  <ControlLabel>Aggregation Time Range <small className="text-muted">(Optional)</small></ControlLabel>
	  <Input
	    id="aggregation_time"
	    type="number"
	    name="aggregation_time"
	    help="Aggregate alerts received in the given number of minutes by logging alerts with the same alert id"
	    value={config.aggregation_time === undefined? alertConfig.aggregation_time : config.aggregation_time}
	    onChange={this.handleChange}
	  />
	  <ControlLabel>Alert Tag <small className="text-muted">(Optional)</small></ControlLabel>
	  <Input
	    id="alert_tag"
	    type="text"
	    name="alert_tag"
	    help="The tag of the generated logs"
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
  },
});

export default LoggingAlertForm;
