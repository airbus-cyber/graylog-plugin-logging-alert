import React from 'react';
import PropTypes from 'prop-types';
import { ControlLabel, FormGroup, HelpBlock } from 'components/graylog';
import lodash from 'lodash';

import { Select, MultiSelect, SourceCodeEditor } from 'components/common';
import { Input } from 'components/bootstrap';
import FormsUtils from 'util/FormsUtils';
import StoreProvider from 'injection/StoreProvider';

const FieldsStore = StoreProvider.getStore('Fields');

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
  };

  static defaultConfig = {
    field_alert_id: 'id',
    severity: 'LOW', 
    separator: ' | ',
    log_body: DEFAULT_BODY_TEMPLATE,
    alert_tag: 'LoggingAlert',
    aggregation_time: 0,
    overflow_tag: 'LoggingOverflow',
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
	    this.propagateChange('body_template', nextValue);
	  };

  availableSeverityTypes = () => {
      return [
        {value: 'HIGH', label: 'High'},
        {value: 'MEDIUM', label: 'Medium'},
        {value: 'LOW', label: 'Low'}, 
        {value: 'INFO', label: 'Info'},  
      ];
  };
  
  availableSplitFields = () => {
	//s'inspirer de FieldRule
	  FieldsStore.loadFields().then((fields) => {
		  //add value to list fields if not present
		  if (config.separator && config.separator !== '' && fields.indexOf(config.separator) < 0) {
			  fields.push(config.separator);
		  }
		  //this.setState({fields: fields});
	  });
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
    const { config, users, validation } = this.props;

    return (
      <React.Fragment>
      <FormGroup controlId="notification-severity"
	          validationState={validation.errors.severity ? 'error' : null}>
	     <ControlLabel>Alert Severity <small className="text-muted">(Optional)</small></ControlLabel>
	     <Select id="notification-severity"
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
	  <FormGroup controlId="notification-log-body" validationState={validation.errors.body_template ? 'error' : null}>
		 <ControlLabel>Body Template</ControlLabel>
		 <SourceCodeEditor id="notification-body-template"
		                   mode="text"
		                   theme="light"
		                   value={config.log_body || ''}
		                   onChange={this.handleBodyTemplateChange} />
		 <HelpBlock>
		   {lodash.get(validation, 'errors.log_body[0]', 'The template to generate the log content form')}
		 </HelpBlock>
	  </FormGroup>
	  <FormGroup controlId="notification-separator">
		 <ControlLabel>Split Fields <small className="text-muted">(Optional)</small></ControlLabel>
		 <MultiSelect id="notification-separator"
		     placeholder="Add Split Fields"
	         required
	         options={this.availableSplitFields()}
	         matchProp="value"
	         value={config.separator}
	         onChange={this.handleChange} 
	     />
		 <HelpBlock>
		   {lodash.get(validation, 'errors.log_body[0]', 'Fields that should be checked to split the alert according to each value by generating a different alert is for each value')}
		 </HelpBlock>
	  </FormGroup>
	  <ControlLabel>Alert Time Range <small className="text-muted">(Optional)</small></ControlLabel>
	  <Input
	    id="alert_time_range"
	    type="number"
	    name="alert_time_range"
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
	  </React.Fragment>
    );
  }
}

export default LoggingAlertForm;
