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

def test_plugin_logging_alert_should_be_registered_issue_50(page: Page):
    page.get_by_role('button', name='System').click()
    page.get_by_role('menuitem', name='Configurations').click()
    page.get_by_role('button', name='Plugins').click()
  
    # note: could also be: await expect(page.getByText('Logging Alert')).toBeVisible();
    # TODO should really by Logging Alert, but this will only be possible once this fix https://github.com/Graylog2/graylog2-server/issues/15939 is released
    expect(page.get_by_role('button', name='Logging')).to_have_text('com.airbus_cyber_security.graylog.events.config.LoggingAlertConfig')

def test_plugin_logging_alert_configuration_save_button_should_close_popup_50(page: Page):
    page.get_by_role('button', name='System').click()
    page.get_by_role('menuitem', name='Configurations').click()
    page.get_by_role('button', name='Plugins').click()
    page.get_by_role('button', name='Logging').click()
    page.get_by_role("button", name="Edit configuration").click()
    page.get_by_text('Save').click()
    print('A')
    expect(page.get_by_text('Update Logging Alert Notification Configuration')).to_have_count(0)
    print('B')
    # TODO...
#    expect(page.get_by_text('Update Logging Alert Notification Configuration').count()).to_equal(0)
#    print('C')
#    expect(page.get_by_text('Update Logging Alert Notification Configuration')).not_to_be_attached()