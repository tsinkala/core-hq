from corehq.apps.hqwebapp.testcases import AdminUserTestCase
from corehq.apps.hqwebapp import selenium
from .util import random_letters
from .util import SeleniumUtils

TEST_PROJECT = selenium.get_user('WEB_USER', exact=False).PROJECT
#Uncomment below to define a project different from the one in settings
#TEST_PROJECT = "my-test-project"


class MobileUserCreationTestCase(SeleniumUtils, AdminUserTestCase):
    settings_mobile_user = selenium.get_user('WEB_USER', exact=False)

    def setUp(self):
        """
        Hook up webdriver. Login in as Admin User
        """
        super(MobileUserCreationTestCase, self).setUp()

    def delete_mobile_user(self, user):
        """
        Deletes a mobile user whose usernname is user (or rather user@project-name.commcarehq.org).
        This method is called by test cases to delete users at will
        :param string: usernane without the domain part
        """
        self._q("_%s" % TEST_PROJECT).click()
        self._q("_Settings & Users").click()
        self._q('///*[@id="pagination-limit"]/option[5]').click() #Show all users (up to 50)
        self._q("_%s" % user).click()
        self._q("_Delete Mobile Worker").click()
        input = self._q('//html/body/div[2]/div[2]/form/div/input')
        input.send_keys("I understand")
        self._q('//html/body/div[2]/div[2]/form/div[2]/button').click()

    def tearDown(self):
        super(MobileUserCreationTestCase, self).tearDown()
        # self._q("_Sign Out").click()
        # self.driver.quit()

    def test_create_mobile_user(self):
        #todo: Test validation as well

        self._q("//html/body/div/header/div/div/hgroup/h1/a/img").click() # Go to home page
        self._q("_%s" % TEST_PROJECT).click() #find_element_by_link_text and click
        self._q("_Settings & Users").click()
        self._q("_New Mobile Worker").click()

        username = self._q("@username") #find element by name
        password = self._q("@password")
        repeat_password = self._q("@password_2")


        #create mobile user with random user name
        name = random_letters()
        username.send_keys(name)
        password.send_keys(name)
        repeat_password.send_keys(name)
        self._q("//html/body/div/div[2]/div[2]/form/div[2]/button").click()

        assert ('User Information' in self.driver.page_source)
        #The username is lower cased when saved
        self.assertEquals(name.lower(), "%s" % self._q(".user_username").text.strip(), "User name not equal '%s'  <=> '%s'"  % (name.lower(), self._q(".user_username").text))

        #The user_domain should be @PROJECT_NAME.commcarehq.org
        self.assertEquals('@%s.commcarehq.org' % TEST_PROJECT, "%s" % self._q(".user_domainname").text, 'Domain name not equal @%s.commcarehq.org' % TEST_PROJECT)

        # Done. delete the user from the database
        self.delete_mobile_user(name.lower())

    def test_edit_mobile_user(self):
        pass
    #create mobile user
    #sign out
    #log in
    #navigate to projects page
    #select project, then
    # self._q("_%s" % TEST_PROJECT).click()
    # self._q("_Settings & Users").click()
    # self._q('///*[@id="pagination-limit"]/option[5]').click() #Show all users (up to 50)
    # self._q("_%s" % user).click()
    # change first name, surname,etc. It would be good to try out invalid input like invalid email




