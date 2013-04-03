from corehq.apps.hqwebapp.testcases import AdminUserTestCase
from corehq.apps.hqwebapp import selenium
from selenium.webdriver.support.ui import Select
from .util import random_letters
from .util import SeleniumUtils

TEST_PROJECT = selenium.get_user('WEB_USER', exact=False).PROJECT
#Uncomment below to define a project different from the one in settings
#TEST_PROJECT = "my-test-project"

class AppBase(SeleniumUtils, AdminUserTestCase):
    settings_web_user = selenium.get_user('WEB_USER', exact=False)

    def setUp(self):
        """
        Hook up webdriver. Login in as Admin User
        """
        super(AppBase, self).setUp()

    def tearDown(self):
        super(AppBase, self).tearDown()
        # self.logout()
        # self.driver.quit()

    def login(self, login_name, password):
        self.assertIn("Sign In", self.driver.page_source, "Not on login page.")

        self._q("_Sign In").click()
        self._q("#id_username").clear()
        self._q("#id_username").send_keys(login_name)
        self._q("#id_password").clear()
        self._q("#id_password").send_keys(password)
        self._q("///button[@type='submit']").click()

    def logout(self):
        # click the primary dropdown to reveal 'Sing Out'
        self._q("///a[@class='btn btn-primary dropdown-toggle']").click()
        self._q("_Sign Out").click()

    def go_to_home(self):
        self.driver.get("/")
        self._q("///a[@href='/homepage/']").click()

    def go_to_home_and_select_project(self, project):
        self.go_to_home()
        self._q("_%s" % project).click()

    def go_to_mobile_workers_list(self, project):
        self.go_to_home_and_select_project(project)
        self._q("_Settings & Users").click()

    def go_to_create_mobile_worker_page(self, project):
        self.go_to_mobile_workers_list(project)
        self._q("_New Mobile Worker").click()

    def create_mobile_user(self, name):
        self.go_to_create_mobile_worker_page(TEST_PROJECT)
        self._q("@username").send_keys(name)
        self._q("@password").send_keys(name)
        self._q("@password_2").send_keys(name)
        self._q("///button[text()='Create Mobile Worker']").click()

    def delete_active_mobile_user(self, user):
        """
        Deletes a mobile user whose usernname is user (or rather user@project-name.commcarehq.org).
        This method is called by test cases to delete users at will
        """
        self.driver.get("/")
        self.go_to_mobile_workers_list(TEST_PROJECT)
        if user not in self.driver.page_source:
            Select(self._q('#pagination-limit')).select_by_visible_text("50 users per page")  # Show all users (up to 50)

        self._q("_%s" % user).click()
        self._q("_Delete Mobile Worker").click()
        input_field = self._q('///input[@data-bind]')
        input_field.send_keys("I understand")
        self._q("///button[text()=' Delete Mobile Worker' and @type='submit']").click()

    def delete_archived_mobile_user(self, user):
        """
        Deletes a mobile user whose usernname is user (or rather user@project-name.commcarehq.org).
        This method is called by test cases to delete users at will
        """
        self.driver.get("/")
        self.go_to_mobile_workers_list(TEST_PROJECT)
        self._q("_Show Archived Mobile Workers").click()
        if user not in self.driver.page_source:
            Select(self._q('#pagination-limit')).select_by_visible_text("50 users per page")  # Show all users (up to 50)
        self._q("_%s" % user).click()
        self._q("_Delete Mobile Worker").click()
        input_field = self._q('///input[@data-bind]')
        input_field.send_keys("I understand")
        self._q("///button[text()=' Delete Mobile Worker' and @type='submit']").click()

    def assert_in_page_source(self, text, message=None):

        # todo: implement logic to ensure that that self.driver.page_source has reached an updated state before
        # doing the assertion
        if message:
            assert(text in self.driver.page_source, message)
        else:
            assert(text in self.driver.page_source)



class MobileUserManagementTestCase(AppBase):

    def test_create_mobile_user_wth_invalid_password(self):
        self.go_to_create_mobile_worker_page(TEST_PROJECT)

        name = random_letters()
        self._q("@username").send_keys(name)

        # test blank password
        self._q("@password").send_keys("")
        self._q("@password_2").send_keys("")
        self._q("///button[text()='Create Mobile Worker']").click()
        assert ('This field is required.' in self.driver.page_source)

        # test mismatched passwords
        self._q("@password").send_keys("one")
        self._q("@password_2").send_keys("two")
        self._q("///button[text()='Create Mobile Worker']").click()
        assert ('Passwords do not match' in self.driver.page_source)

    def test_create_mobile_user(self):
        name = random_letters()
        self.create_mobile_user(name)

        assert ('User Information' in self.driver.page_source)

        #The username is lower cased when saved
        self.assertEquals(name.lower(), "%s" % self._q(".user_username").text.strip(), "User name not equal '%s'  <=> '%s'"  % (name.lower(), self._q(".user_username").text))

        #The user_domain should be @PROJECT_NAME.commcarehq.org
        self.assertEquals('@%s.commcarehq.org' % TEST_PROJECT, "%s" % self._q(".user_domainname").text,
                          'Domain name not equal @%s.commcarehq.org' % TEST_PROJECT)

        # Done. delete the user from the database
        self.delete_active_mobile_user(name.lower())

    def test_edit_mobile_user(self):
        name = random_letters(8).lower()
        self.create_mobile_user(name)
        self.logout()
        self.login(self.username, self.password)
        self.go_to_mobile_workers_list(TEST_PROJECT)

        # display possibly all mobile users in the project
        if name not in self.driver.page_source:
            Select(self._q('#pagination-limit')).select_by_visible_text("50 users per page")

        self._q("_%s" % name).click()

        first_name = "Lukundo"
        last_name = "Sinkala"
        bad_email = "grace.com"
        correct_email = "grace@testmail.com"

        self._q("#id_first_name").clear()
        self._q("#id_first_name").send_keys(first_name)
        self._q("#id_last_name").clear()
        self._q("#id_last_name").send_keys(last_name)
        self._q("#id_email").clear()

        # test invalid email format
        self._q("#id_email").send_keys(bad_email)
        # make sure you select the right button (There is another hidden button with same text)
        self._q("///form[@name='user_details']//button[text()='Update Information']").click()
        self.assertIn('Enter a valid e-mail address.', self.driver.page_source, "Email error message should show")

        self._q("#id_email").clear()

        self._q("#id_email").send_keys(correct_email)
        # make sure you select the right button (There is another hidden button with same text)
        self._q("///form[@name='user_details']//button[text()='Update Information']").click()

        self.assertIn('Changes saved for user "%s@%s.commcarehq.org"' % (name, TEST_PROJECT), self.driver.page_source)
        self.assertIn(first_name, self.driver.page_source)
        self.assertIn(last_name, self.driver.page_source)
        self.assertIn(correct_email, self.driver.page_source)

        #test resetting password
        self._q("_Reset Password").click()
        self._q("#id_new_password1").clear()
        self._q("#id_new_password1").send_keys("test2")
        self._q("#id_new_password2").clear()
        self._q("#id_new_password2").send_keys("test2")
        self._q("///button[text()='Reset Password']").click()
        self.assertIn("Password changed successfully!", self.driver.page_source)
        self._q("_Close").click()
        # self.driver.get("/")  # get focus from dialog to main window
        self.delete_active_mobile_user(name)

    def test_archive_mobile_user(self):
        input_name = random_letters()

        self.create_mobile_user(input_name)
        self.go_to_mobile_workers_list(TEST_PROJECT)
        name = input_name.lower()
        if name not in self.driver.page_source:
            Select(self._q('#pagination-limit')).select_by_visible_text("50 users per page")

        user_id = self._q("_%s" % name).get_attribute('outerHTML').split("/")[-3]
        self._q("///a[@href='#%s']" % user_id).click()
        assert "Are you sure you want to" in self.driver.page_source
        self._q("///*[@id='%s']//a[text()='Archive']" % user_id).click()
        assert "Archived Users" in self.driver.page_source, "Archived Users' list might be empty"        
        self.delete_archived_mobile_user(name)


class WebUserManagementTestCase(AppBase):

    def test_add_web_user(self):
        self.go_to_mobile_workers_list(TEST_PROJECT)
        self._q("_Web Users").click()
        self._q("_Invite Web User").click()
        self._q("#id_email").clear()
        self._q("#id_email").send_keys("bademail.com")
        self._q("///button[text()='Send Invite']").click()
        self.assertIn('Enter a valid e-mail address.', self.driver.page_source, "Email error message should show")
        self._q("#id_email").clear()
        name = random_letters()
        self._q("#id_email").send_keys("%s@testit.com" % name)
        self._q("///button[text()='Send Invite']").click()
        assert "Invitation sent to %s@testit.com" % name in self.driver.page_source

    def test_edit_web_user(self):
        """
        Tests editing Web User. For this test to work, the Web User defined in settings has to be an actual web user
        created through email invitation
        """
        self.go_to_mobile_workers_list(TEST_PROJECT)
        self._q("_Web Users").click()
        short_user_name = self.settings_web_user.USERNAME.split('@')[0]
        self._q("///a[*[text()='%s']]" % short_user_name).click()

        # Let's make several edits and saves
        users_details = [["Field Implementer", "David", "Livingstone"], ["App Editor", "Nelson", "Mandela"], ["Read Only", "Eliza", "Phiri"], ["Admin", "John", "Bwalya"]]
        for user_details in users_details:
            role, f_name, l_name = user_details
            self._q("///a[*[text()='%s']]" % short_user_name).click()
            self._q("#id_first_name").clear()
            self._q("#id_first_name").send_keys(f_name)
            self._q("#id_last_name").clear()
            self._q("#id_last_name").send_keys(l_name)
            Select(self._q("#id_role")).select_by_visible_text(role)
            self._q("///button[text()='Update Information']").click()
            self.assert_in_page_source("Changes saved for user")
            self._q("_Web Users").click()
            self.assert_in_page_source(role)
            self.assert_in_page_source("%s %s" % (f_name, l_name))
            # we want to test further that role, f_name, l_name appear in same record (table row)
            assert self._q("///tr[td[contains(text(),'%(role)s')] and td[contains(text(),'%(f_name)s %(l_name)s')]]" %
                       {'role':role, 'f_name':f_name, 'l_name':l_name})