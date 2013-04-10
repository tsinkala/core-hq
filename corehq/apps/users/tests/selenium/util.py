import random
import string


class SeleniumUtils:
    driver = None

    def _q(self, str):
        dr = self.driver

        value = str[1:]

        if str.startswith('#'):
            return dr.find_element_by_id(value)
        elif str.startswith('.'):
            return dr.find_element_by_class_name(value)
        elif str.startswith('_'):
            return dr.find_element_by_link_text(value)
        elif str.startswith('-'):
            return dr.find_element_by_partial_link_text(value)
        elif str.startswith('@'):
            return dr.find_element_by_name(value)
        elif str.startswith('/'):
            return dr.find_element_by_xpath(value)

        return dr.find_elements_by_tag_name(str)

    def assert_in_page_source(self, text, message=None):

        # todo: implement logic to ensure that that self.driver.page_source has reached an updated state before
        # doing the assertion
        if message:
            assert(text in self.driver.page_source, message)
        else:
            assert(text in self.driver.page_source)



def random_letters(length=10):
    """
    returns a random string consisting of a maximum of ten letters
    :param length: int
    :return: string
    """
    return ''.join([random.choice(string.letters) for i in range(min(length, 10))])
