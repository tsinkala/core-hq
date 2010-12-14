#from django.conf.urls.defaults import patterns, url
from django.conf.urls.defaults import *

urlpatterns = patterns('corehq.apps.users.views',
    (r'^$', 'users'),
    url(r'my_account$', 'my_account', name='my_account'),
    url(r'my_phone_numbers$', 'my_phone_numbers', name='my_phone_numbers'),
    url(r'my_commcare_accounts$', 'my_commcare_accounts', name='my_commcare_accounts'),
    url(r'my_domains$', 'my_domains', name='my_domains'),
    url(r'account/(?P<couch_id>[\w-]+)/?$', 'account', name='user_account'),
    url(r'phone_numbers/(?P<couch_id>[\w-]+)/?$', 'phone_numbers', name='phone_numbers'),
    url(r'commcare_accounts/(?P<couch_id>[\w-]+)/?$', 'commcare_accounts', name='commcare_accounts'),
    url(r'domain_accounts/(?P<couch_id>[\w-]+)/?$', 'domain_accounts', name='domain_accounts'),
    url(r'delete_phone_number/(?P<user_id>[\w-]+)/(?P<phone_number>[\w-]+)/?$', 
        'delete_phone_number',
        name='delete_phone_number'),
    url(r'add_domain_membership/(?P<user_id>[\w-]+)/(?P<domain_name>[\w-]+)/?$', 
        'add_domain_membership',
        name='add_domain_membership'),
    url(r'delete_domain_membership/(?P<user_id>[\w-]+)/(?P<domain_name>[\w-]+)/?$', 
        'delete_domain_membership',
        name='delete_domain_membership'),
    url(r'all/?$', 'all_users', name='all_users'),
)
