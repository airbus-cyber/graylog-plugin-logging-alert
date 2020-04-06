import React from 'react';
import PropTypes from 'prop-types';
import { ControlLabel, FormGroup, HelpBlock } from 'components/graylog';
import lodash from 'lodash';
import naturalSort from 'javascript-natural-sort';
import LoggingAlertConfig from "../LoggingAlertConfig";

import { Select, MultiSelect, SourceCodeEditor } from 'components/common';
import { Input } from 'components/bootstrap';
import FormsUtils from 'util/FormsUtils';

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

class LoggingAlertForm extends React.Component {
  static propTypes = {
    config: PropTypes.object.isRequired,
    validation: PropTypes.object.isRequired,
    onChange: PropTypes.func.isRequired,
  	fields: PropTypes.array.isRequired,
  };

  static defaultConfig = {
    severity: LoggingAlertConfig.propTypes.config.severity,
    log_body: LoggingAlertConfig.propTypes.config.log_body,
    alert_tag: LoggingAlertConfig.propTypes.config.alert_tag,
    aggregation_time: LoggingAlertConfig.propTypes.config.aggregation_time,
    split_fields: [],
  	single_notification: false,
  	comment: '',
  };
  
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
  	return nextValue => this.propagateChange(key, nextValue === '' ? [] : nextValue.split(','));
  };

  availableSeverityTypes = () => {
      return [
        {value: 'HIGH', label: 'High'},
        {value: 'MEDIUM', label: 'Medium'},
        {value: 'LOW', label: 'Low'}, 
        {value: 'INFO', label: 'Info'},  
      ];
  };
  
  /*availableSplitFields = () => {
	//s'inspirer de FieldRule
	  //return fields.map(field => ({ label: field.label, value: field.username }));
  };*/

  _formatOption = (key, value) => {
  	return {value: value, label: key};
  };
    
  activeSeverityType = (type) => {
      return this.availableSeverityTypes().filter((t) => t.value === type)[0].label;
  };
  
  onSeverityTypeSelect = (id) => {
      const update = ObjectUtils.clone(config);
      update['severity'] = id;
      this.setState({ config: update });
  };
  
  render() {
    const { config, validation, fields } = this.props;
	  let formattedOptions = null;
	  if(fields) {
		  formattedOptions = Object.keys(fields).map(key => this._formatOption(fields[key], fields[key]))
			  .sort((s1, s2) => naturalSort(s1.label.toLowerCase(), s2.label.toLowerCase()));
	  }

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
	         value={config.severity}
	         onChange={this.handleChange}
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
		                   value={config.log_body || ''}
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
	    value={config.aggregation_time}
	    onChange={this.handleChange}
	  />
	  <ControlLabel>Alert Tag <small className="text-muted">(Optional)</small></ControlLabel>
	  <Input
	    id="alert_tag"
	    type="text"
	    name="alert_tag"
	    help="The tag of the generated logs"
	    value={config.alert_tag}
	    onChange={this.handleChange}
	  />
	  <div>
		  <ControlLabel for="single_notification">Single Message <small className='text-muted'>(Optional)</small></ControlLabel>
		  <Input
			  id="single_notification"
			  type="checkbox"
			  name="single_notification"
			  help="Check this box to send only one message by alert"
			  value={config.single_notification}
			  onChange={this.handleChange}
		  />
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
}

export default LoggingAlertForm;
