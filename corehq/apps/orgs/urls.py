from corehq.apps.users.views import UploadCommCareUsers
from django.conf.urls.defaults import *
domain_name_re = r"[\w\.:-]+"
org_re = '[\w\.-]+'

urlpatterns = patterns('corehq.apps.orgs.views',
    url(r'^$', 'orgs_base', name='orgs_base'),
    url(r'^(?P<org>%s)/$' % org_re,'orgs_landing', name='orgs_landing'),
    url(r'^(?P<org>%s)/update_info/$' % org_re, 'orgs_update_info', name='orgs_update_info'),
    url(r'^(?P<org>%s)/get_data/$' % org_re, 'get_data', name='get_data'),
    url(r'^(?P<org>%s)/add_project/$' % org_re, 'orgs_add_project', name='orgs_add_project'),
    url(r'^(?P<org>%s)/new_project/$' % org_re, 'orgs_new_project', name='orgs_new_project'),
    url(r'^(?P<org>%s)/(?P<domain>%s)/remove_project/$' % (org_re, domain_name_re), 'orgs_remove_domain', name='orgs_remove_domain'),
    url(r'^(?P<org>%s)/(?P<team_id>[ \w-]+)/add_member/$' % org_re, 'orgs_add_member', name='orgs_add_member'),
    url(r'^(?P<org>%s)/(?P<member_id>[\w\.-]+)/remove_member/$' % org_re, 'orgs_remove_member', name='orgs_remove_member'),
    url(r'^(?P<org>%s)/add_team/$' % org_re, 'orgs_add_team', name='orgs_add_team'),
    url(r'^(?P<org>%s)/logo/$' % org_re, 'orgs_logo', name='orgs_logo'),
    url(r'^(?P<org>%s)/members/$' % org_re, 'orgs_members', name='orgs_members'),
    url(r'^(?P<org>%s)/teams/$' % org_re, 'orgs_teams', name='orgs_teams'),
    url(r'^(?P<org>%s)/teams/add_team/$' % org_re, 'add_team', name='add_team'),
    url(r'^(?P<org>%s)/teams/(?P<team_id>[ \w-]+)/$' % org_re, 'orgs_team_members', name='orgs_team_members'),
    url(r'^(?P<org>%s)/teams/(?P<team_id>[ \w-]+)/add_all/$' % org_re, 'add_all_to_team', name='add_all_to_team'),
    url(r'^(?P<org>%s)/teams/(?P<team_id>[ \w-]+)/remove_all/$' % org_re, 'remove_all_from_team', name='remove_all_from_team'),
    url(r'^(?P<org>%s)/teams/(?P<team_id>[ \w-]+)/(?P<domain>%s)/add_domain/$' % (org_re, domain_name_re), 'add_domain_to_team', name='add_domain_to_team'),
    url(r'^(?P<org>%s)/teams/(?P<team_id>[ \w-]+)/(?P<domain>%s)/(?P<role_label>[\w-]+)/set_permission/$' % (org_re, domain_name_re), 'set_team_permission_for_domain', name='set_team_permission_for_domain'),
    url(r'^(?P<org>%s)/(?P<user_id>[\w\.-]+)/(?P<role_label>[\w\.-]+)/set_org_permissions/$' % org_re, 'orgs_change_role', name='orgs_change_role'),
    url(r'^(?P<org>%s)/teams/(?P<team_id>[ \w-]+)/(?P<domain>%s)/remove_domain/$' % (org_re, domain_name_re), 'remove_domain_from_team', name='remove_domain_from_team'),
    url(r'^(?P<org>%s)/teams/(?P<team_id>[ \w-]+)/delete_team/$' % org_re, 'delete_team', name='delete_team'),
    url(r'^(?P<org>%s)/teams/(?P<record_id>[ \w-]+)/undo_delete_team/$' % org_re, 'undo_delete_team', name='undo_delete_team'),
    url(r'^(?P<org>%s)/teams/(?P<team_id>[ \w-]+)/(?P<couch_user_id>[\w-]+)/join_team/$' % org_re, 'join_team', name='join_team'),
    url(r'^(?P<org>%s)/teams/(?P<team_id>[ \w-]+)/(?P<couch_user_id>[\w-]+)/leave_team/$' % org_re, 'leave_team', name='leave_team')
)