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
    expect(page.get_by_role('button', name='Logging')).to_have_text('Logging Alert')

