from django.test import TestCase
from corehq.apps.orgs.models import Organization, Team
from corehq.apps.sms.models import SMSLog
from corehq.apps.users.models import WebUser, DomainMembership
from dimagi.utils.couch.resource_conflict import repeat


class OrganizationsTest(TestCase):

    def setUp(self):
        self.domain = 'mockdomain'
        all_logs = SMSLog.by_domain_asc(self.domain).all()
        for log in all_logs:
            log.delete()
        self.user = 'username'
        self.password = 'password'
        self.couch_user = WebUser.create(self.domain, self.user, self.password)
        self.couch_user.save()
        self.dcs = '8'
        self.message_ascii = 'O It Works O'
        self.message_utf_hex = '0939093F0928094D092609400020091509300924093E00200939094800200907093800200938092E092F00200915093E092E002009390948003F'

        self.organization = Organization(name='mockorganization123', title='Mock Organization')
        self.organization.save()
        self.organization.add_member(self.couch_user.get_id)
        self.team = Team(name='team', organization='mockorganization123')
        self.team.save()




    def tearDown(self):
        self.couch_user.delete()
        self.organization.delete()
        self.team.delete()

    def testPermissionsForOrganizations(self):
        self.organization.add_member(self.couch_user.get_id)
        self.couch_user.organization_manager.add_membership(self.couch_user, item=self.organization.name)
        self.couch_user.organization_manager.set_role(self.couch_user, self.organization.name, 'admin')
        self.couch_user.save()
        self.membership = self.couch_user.organization_manager.get_membership(self.couch_user, item=self.organization.name)
        assert self.membership.is_admin == True
        assert self.membership.subject == 'mockorganization123'
        self.couch_user.organization_manager.delete_membership(self.couch_user, item=self.organization.name)
        assert self.couch_user.organization_memberships == []
        self.couch_user.save()


    def testMembershipMigration(self):
        self.domain_membership_json = {u'doc_type': u'DomainMembership', u'domain': u'mockdomain', u'last_login': None, u'role_id': u'ed77b6f64d251e2aa023593044df90fa', u'is_admin': False, u'override_global_tz': False, u'timezone': u'UTC', u'date_joined': None, u'subject': None}
        self.domain_membership = DomainMembership.wrap(self.domain_membership_json)

        assert self.domain_membership.to_json() == {u'doc_type': u'DomainMembership', u'domain': None, u'last_login': None, u'role_id': u'ed77b6f64d251e2aa023593044df90fa', u'is_admin': False, u'override_global_tz': False, u'timezone': u'UTC', u'date_joined': None, u'subject': u'mockdomain'}


#    def testTeamMemberships(self):
#        self.team.add_member(self.couch_user._id)
#        self.couch_user.teams.append([self.team.name, self.team.get_id])
#        self.team.add_domain_membership(self.domain)
#        self.team.save()
#        self.team.set_role(self.domain, 'admin')
#        self.team.save()
#        import pdb
#        pdb.set_trace()
#        assert self.couch_user.get_role(item=self.domain).name[1] == 'Admin (' + self.domain + ')'



