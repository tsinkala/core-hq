from corehq.apps.hqwebapp.testcases import WebUserTestCase, AdminUserTestCase
from corehq.apps.hqwebapp import selenium
from selenium.webdriver.support.ui import Select
from corehq.apps.users.tests.selenium.util import SeleniumUtils, random_letters
from corehq.apps.reports.tests.selenium.test_reports import report_names
from datetime import datetime, timedelta
import time
from random import randrange

TEST_PROJECT = selenium.get_user('WEB_USER', exact=False).PROJECT


class AppBase(SeleniumUtils, WebUserTestCase):

    def setUp(self):
        super(AppBase, self).setUp()
        self._q("_%s" % TEST_PROJECT).click()
        self._q('_Reports').click()
        assert 'Project Reports' in self.driver.page_source

    def show_filters_if_hidden(self):
        toggle = self._q("#toggle-report-filters")
        if toggle.text == 'Show Filter Options':
            toggle.click()


def saving_report(driver):
    if 'New Saved Report' in driver.page_source:
        return True

    return False


class SaveReportsTestCase(AppBase):
    max_rpt_save_time = 5

    def delete_saved_report(self, report, report_description, report_name):
        # wait for report to save and dialog to close
        self.wait_until_not(saving_report, time=self.max_rpt_save_time)
        self._q("_My Saved Reports").click()
        # A row is created with our report, report name, and description. We don't want to keep it but delete it
        self._q("///tr[td[text()='%s'] and td[text()='%s'] and td[a[text()='%s']]]/td/button" %
                (report, report_description, report_name)).click()

    def open_and_partially_fill_save_dialog(self, report, report_description, report_name):
        self._q("_%s" % report).click()
        self.show_filters_if_hidden()
        self._q("///button[contains(text(), 'Save...')]").click()
        self._q("#name").clear()
        self._q("#name").send_keys(report_name)
        self._q("@description").clear()
        self._q("@description").send_keys(report_description)

    def get_name_and_description(self, report):
        """
        returns a tuple containing name and description with timestamps. This is to ensure uniqueness in report names
        :param report: string
        :return:
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_name = "My %s. %s" % (report, timestamp)
        report_description = "%s: Description for %s" % (timestamp, report)
        return report_name, report_description

    def save_report_and_cleanup(self, report, report_description, report_name):
        self._q("///*[text()='Save']").click()
        self.delete_saved_report(report, report_description, report_name)

    def test_save_with_default_date_options(self):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for report in report_names:
            if report == 'De-Identified Export':
                #todo: resolve this report missing on my local install
                continue
            report_name = "My %s. %s" % (report, timestamp)

            report_description = "%s: Description for %s" % (timestamp, report)
            self._q("_%s" % report).click()
            self.wait_until_not(lambda driver: 'Fetching additional data' in driver.page_source,
                                time=self.max_rpt_save_time)
            self.show_filters_if_hidden()

            # open the report save dialog
            self._q("///button[contains(text(), 'Save...')]").click()
            self._q("#name").clear()
            self._q("#name").send_keys(report_name)
            self._q("@description").clear()
            self._q("@description").send_keys(report_description)
            self._q("///*[text()='Save']").click()

            # wait for report to save and dialog to close
            self.wait_until_not(saving_report, time=self.max_rpt_save_time)

            self._q("_My Saved Reports").click()

            # A row is created with our report, report name, and description. We don't want to keep it but delete it
            self._q("///tr[td[text()='%s'] and td[text()='%s'] and td[a[text()='%s']]]/td/button" %
                    (report, report_description, report_name)).click()

    def test_date_range_with_simple_select(self):
        """
        test with simple select date range
        """
        report = 'Daily Form Activity'
        report_name, report_description = self.get_name_and_description(report)
        
        self.open_and_partially_fill_save_dialog(report, report_description, report_name)
        Select(self._q("@date_range")).select_by_visible_text("Last 30 days")
        self.save_report_and_cleanup(report, report_description, report_name)

    def test_date_range_with_arbitrary_days(self):
        """
        test with user entered arbitrary days
        """
        report = 'Daily Form Activity'
        report_name, report_description = self.get_name_and_description(report)
        self.open_and_partially_fill_save_dialog(report, report_description, report_name)

        Select(self._q("@date_range")).select_by_visible_text("Days ago")
        random_days = randrange(1, 100)
        self._q("@days").clear()
        self._q("@days").send_keys(random_days)
        self.save_report_and_cleanup(report, report_description, report_name)

    def test_date_range_with_arbitrary_start_date(self):
        """
        test with user entered arbitrary days
        """

        report = 'Daily Form Activity'
        report_name, report_description = self.get_name_and_description(report)
        self.open_and_partially_fill_save_dialog(report, report_description, report_name)

        Select(self._q("@date_range")).select_by_visible_text("Since a date")
        random_date = (datetime.now() - timedelta(randrange(1, 100))).strftime("%Y-%m-%d")
        self._q("///input[@name='start_date']").clear()
        self._q("///input[@name='start_date']").send_keys(random_date)
        self.save_report_and_cleanup(report, report_description, report_name)

    def test_date_range_with_arbitrary_start_and_end_dates(self):
        """
        test with user arbitrary start and end dates
        """

        report = 'Daily Form Activity'
        report_name, report_description = self.get_name_and_description(report)
        self.open_and_partially_fill_save_dialog(report, report_description, report_name)

        Select(self._q("@date_range")).select_by_visible_text("From a date to a")
        from_date = (datetime.now() - timedelta(randrange(50, 100))).strftime("%Y-%m-%d")

        self._q("///input[@name='start_date']").clear()
        self._q("///input[@name='start_date']").send_keys(from_date)

        to_date = (datetime.now() - timedelta(randrange(50))).strftime("%Y-%m-%d")
        self._q("///input[@name='end_date']").clear()
        self._q("///input[@name='end_date']").send_keys(to_date)
        self.save_report_and_cleanup(report, report_description, report_name)

    def test_schedule_saved_report(self):

        for report in ['Daily Form Activity', 'Submissions By Form']:

            report_name, report_description = self.get_name_and_description(report)
            self.open_and_partially_fill_save_dialog(report, report_description, report_name)
            self._q("///*[text()='Save']").click()
            self.wait_until_not(saving_report, time=self.max_rpt_save_time)

            self._q("_My Saved Reports").click()
            self._q("_My Scheduled Reports").click()
            self._q("_Create a New Scheduled Report").click()
            self._q("_Add all").click()
            self._q("#id_recipient_emails").clear()
            recipient_email = "%s@seltest.com" % random_letters()
            self._q("#id_recipient_emails").send_keys(recipient_email)
            self._q("#submit-id-submit").click()

            # wait for some background process
            self.wait_until(lambda driver: "Scheduled report added!" in driver.page_source, time=self.max_rpt_save_time)
            self._q("_My Scheduled Reports").click()

            # a row shows with the report name, type, and recipients email
            assert (self._q("///tr[td[contains(text(),'%(recipient_email)s')] and //a[contains(text(),'%(given_name)s (%(report_type)s)')]]"
                    % {'given_name': report_name, 'report_type': report, 'recipient_email':recipient_email}), "Scheduled report not found")
            
            # Done. Delete the scheduled report
            # Click the right 'Delete' button
            self._q("///tr[td[contains(text(),'%(recipient_email)s')] and //a[contains(text(),'%(given_name)s (%(report_type)s)')]]//button[@class='btn btn-danger']"
                    % {'given_name': report_name, 'report_type': report, 'recipient_email':recipient_email}).click()
            # Click 'Stop Sending' button to confirm
            self._q("///tr[td[contains(text(),'%(recipient_email)s')] and //a[contains(text(),'%(given_name)s (%(report_type)s)')]]//button[text()='Stop Sending']"
                    % {'given_name': report_name, 'report_type': report, 'recipient_email':recipient_email}).click()

            self.delete_saved_report(report, report_description, report_name)
