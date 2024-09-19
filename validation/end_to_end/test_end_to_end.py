from pytest import fixture
from graylog.driver import Driver

from playwright.sync_api import Page, expect


@fixture(scope="function", autouse=True)
def before_each_after_each(page: Page):
    subject = Driver('../../runtime')
    subject.start()
    subject.configure_telemetry()

    page.goto('http://127.0.0.1:9000/')
    # note: could also be: getByRole('textbox', { name: 'Username' })
    page.get_by_label('Username').fill('admin')
    page.get_by_label('Password').fill('admin')
    page.get_by_role('button', name='Sign in').click()

    yield
    subject.stop()

def _go_to_plugin_configuration(page: Page):
    page.get_by_role('button', name='System').click()
    page.get_by_role('menuitem', name='Configurations').click()
    page.get_by_title('Plugins').click()
    page.get_by_title('Logging Alert').click()

def test_plugin_logging_alert_should_be_registered_issue_50(page: Page):
    _go_to_plugin_configuration(page)
    expect(page.get_by_title('Logging Alert')).to_be_visible()

def test_plugin_logging_alert_configuration_save_button_should_close_popup_issue_50(page: Page):
    _go_to_plugin_configuration(page)
    page.get_by_role('button', name='Edit configuration').click()
    page.get_by_text('Save').click()
    expect(page.get_by_text('Update Logging Alert Notification Configuration')).not_to_be_attached()

def test_plugin_logging_alert_configuration_save_button_update_should_not_fail_issue_50(page: Page):
    _go_to_plugin_configuration(page)
    page.get_by_role('button', name='Edit configuration').click()
    # note: we could also have done something with page.on('response', lambda response: print('<<', response.status, response.url, response.request.method, response.ok))
    with page.expect_response(lambda response: response.request.method == 'PUT' and '/api/system/cluster_config/' in response.url) as event:
        page.get_by_text('Save').click()
        assert event.value.ok

def test_plugin_logging_alert_configuration_cancel_button_should_revert_changes_issue_50(page: Page):
    _go_to_plugin_configuration(page)
    page.get_by_role('button', name='Edit configuration').click()
    page.get_by_label('Line Break Substitution').fill('+')
    page.get_by_text('Cancel').click()
    page.get_by_role('button', name='Edit configuration').click()
    expect(page.get_by_label('Line Break Substitution')).to_have_value(' | ')

def test_plugin_logging_alert_configuration_cancel_button_should_close_popup_issue_50(page: Page):
    _go_to_plugin_configuration(page)
    page.get_by_role('button', name='Edit configuration').click()
    page.get_by_text('Cancel').click()
    expect(page.get_by_text('Update Logging Alert Notification Configuration')).not_to_be_attached()

def test_plugin_logging_alert_configuration_window_close_should_close_popup_issue_50(page: Page):
    _go_to_plugin_configuration(page)
    page.get_by_role('button', name='Edit configuration').click()
    page.get_by_text("×Close").click()
    expect(page.get_by_text('Update Logging Alert Notification Configuration')).not_to_be_attached()
