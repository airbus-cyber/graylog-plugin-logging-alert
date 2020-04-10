import React from 'react';
import PropTypes from 'prop-types';
import { ControlLabel, FormGroup, HelpBlock } from 'components/graylog';
import lodash from 'lodash';
import naturalSort from 'javascript-natural-sort';

import { Select, MultiSelect, SourceCodeEditor } from 'components/common';
import { Input } from 'components/bootstrap';
import FormsUtils from 'util/FormsUtils';

import Reflux from 'reflux';
import createReactClass from 'create-react-class';
import StoreProvider from 'injection/StoreProvider';
import ActionsProvider from 'injection/ActionsProvider';
const ConfigurationsStore = StoreProvider.getStore('Configurations');
const ConfigurationActions = ActionsProvider.getActions('Configuration');

const DEFAULT_BODY_TEMPLATE = 'type: alert'  + '\n' +
	'id: ${logging_alert.id}'  + '\n' +
	'severity: ${logging_alert.severity}' + '\n' +
	'app: graylog'  + '\n' +
	'subject: ${alertCondition.title}' + '\n' +
	'body: ${check_result.resultDescription}' + '\n' +
	'src: ${message.fields.src_ip}' + '\n' +
	'src_category: ${message.fields.src_category}' + '\n' +
	'dest: ${message.fields.dest_ip}' + '\n' +
	'dest_category: ${message.fields.dest_category}';

const LoggingAlertForm = createReactClass({
	mixins: [Reflux.connect(ConfigurationsStore)],
	propTypes: {
    config: PropTypes.object.isRequired,
    validation: PropTypes.object.isRequired,
    onChange: PropTypes.func.isRequired,
  	fields: PropTypes.array.isRequired,
  },

	getInitialState() {
		return {
			configurations: null,
		};
	},

	LOGGING_ALERT_CONFIG: 'com.airbus_cyber_security.graylog.config.LoggingAlertConfig',

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
  	return nextValue => this.propagateChange(key, nextValue === '' ? [] : nextValue.split(','));
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

  getAlertConfig() {
  	if (this.state.configuration && this.state.configuration[this.LOGGING_ALERT_CONFIG]) {
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
			comment: '',
		}
	}
  },
    
  render() {
    const { config, validation, fields, configurations } = this.props;
    let formattedOptions = null;
    if(fields) {
    	formattedOptions = Object.keys(fields).map(key => this._formatOption(fields[key], fields[key]))
			.sort((s1, s2) => naturalSort(s1.label.toLowerCase(), s2.label.toLowerCase()));
    }

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
	         value={alertConfig.severity}
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
		                   value={alertConfig.log_body || ''}
		                   onChange={this.handleBodyTemplateChange} />
		 <HelpBlock>
		   {lodash.get(validation, 'errors.log_body[0]', 'The template to generate the log content form')}
		 </HelpBlock>
	  </FormGroup>
	  <FormGroup controlId="split_fields">
		 <ControlLabel>Split Fields <small className="text-muted">(Optional)</small></ControlLabel>
		 <MultiSelect id="split_fields"
		     placeholder="Add Split Fields"
	         required
	         options={formattedOptions}
	         matchProp="value"
	         value={Array.isArray(config.split_fields) ? config.split_fields.join(',') : ''}
	         onChange={this.handleFieldsChange('split_fields')}
	     />
		 <HelpBlock>
		   Fields that should be checked to split the alert according to each value by generating a different alert is for each value
		 </HelpBlock>
	  </FormGroup>
	  <ControlLabel>Alert Time Range <small className="text-muted">(Optional)</small></ControlLabel>
	  <Input
	    id="aggregation_time"
	    type="number"
	    name="aggregation_time"
	    help="Aggregate alerts received in the given number of minutes by logging alerts with the same alert id"
	    value={alertConfig.aggregation_time}
	    onChange={this.handleChange}
	  />
	  <ControlLabel>Alert Tag <small className="text-muted">(Optional)</small></ControlLabel>
	  <Input
	    id="alert_tag"
	    type="text"
	    name="alert_tag"
	    help="The tag of the generated logs"
	    value={alertConfig.alert_tag}
	    onChange={this.handleChange}
	  />
	  <div>
		  <Input
			  id="single_notification"
			  type="checkbox"
			  name="single_notification"
			  value={config.single_notification}
			  onChange={this.handleChange}
			  style={{position: 'absolute'}}
		  />
		  <label style={{padding: '10px 20px'}}>Single Message <small className='text-muted'>(Optional)</small></label>
		  <HelpBlock>
			  Check this box to send only one message by alert
		  </HelpBlock>
	  </div>
		  <ControlLabel>Comment <small className="text-muted">(Optional)</small></ControlLabel>
		  <Input
			  id="comment"
			  type="text"
			  name="comment"
			  help="Comment about the configuration"
			  value={config.comment}
			  onChange={this.handleChange}
		  />
	  </React.Fragment>
    );
  }
})

export default LoggingAlertForm;
