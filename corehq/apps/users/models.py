"""
couch models go here
"""
from __future__ import absolute_import

from datetime import datetime
import functools
import logging
import re
from dimagi.utils.decorators.memoized import memoized
from dimagi.utils.make_uuid import random_hex
from dimagi.utils.modules import to_function

from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.sites.models import Site
from django.core.urlresolvers import reverse
from django.core.exceptions import ValidationError
from django.template.loader import render_to_string
from corehq.apps.domain.models import Domain

from couchdbkit.ext.django.schema import *
from couchdbkit.resource import ResourceNotFound
from casexml.apps.case.models import CommCareCase

from casexml.apps.phone.models import User as CaseXMLUser

from corehq.apps.domain.shortcuts import create_user
from corehq.apps.domain.utils import normalize_domain_name
from corehq.apps.reports.models import ReportNotification, HQUserType
from corehq.apps.users.util import normalize_username, user_data_from_registration_form, format_username, raw_username, cc_user_domain
from corehq.apps.users.xml import group_fixture
from corehq.apps.sms.mixin import CommCareMobileContactMixin
from couchforms.models import XFormInstance

from dimagi.utils.couch.database import get_db
from dimagi.utils.couch.undo import DeleteRecord, DELETED_SUFFIX
from dimagi.utils.django.email import send_HTML_email
from dimagi.utils.mixins import UnicodeMixIn
from dimagi.utils.dates import force_to_datetime
from dimagi.utils.django.database import get_unique_value


COUCH_USER_AUTOCREATED_STATUS = 'autocreated'

def _add_to_list(list, obj, default):
    if obj in list:
        list.remove(obj)
    if default:
        ret = [obj]
        ret.extend(list)
        return ret
    else:
        list.append(obj)
    return list


def _get_default(list):
    return list[0] if list else None

class OldPermissions(object):
    EDIT_WEB_USERS = 'edit-users'
    EDIT_COMMCARE_USERS = 'edit-commcare-users'
    EDIT_DATA = 'edit-data'
    EDIT_APPS = 'edit-apps'

    VIEW_REPORTS = 'view-reports'
    VIEW_REPORT = 'view-report'

    AVAILABLE_PERMISSIONS = [EDIT_DATA, EDIT_WEB_USERS, EDIT_COMMCARE_USERS, EDIT_APPS, VIEW_REPORTS, VIEW_REPORT]
    perms = 'EDIT_DATA, EDIT_WEB_USERS, EDIT_COMMCARE_USERS, EDIT_APPS, VIEW_REPORTS, VIEW_REPORT'.split(', ')
    old_to_new = dict([(locals()[attr], attr.lower()) for attr in perms])

    @classmethod
    def to_new(cls, old_permission):
        return cls.old_to_new[old_permission]



class OldRoles(object):
    ROLES = (
        ('edit-apps', 'App Editor', set([OldPermissions.EDIT_APPS])),
        ('field-implementer', 'Field Implementer', set([OldPermissions.EDIT_COMMCARE_USERS])),
        ('read-only', 'Read Only', set([]))
    )

    @classmethod
    def get_role_labels(cls):
        return tuple([('admin', 'Admin')] + [(key, label) for (key, label, _) in cls.ROLES])

    @classmethod
    def get_role_mapping(cls):
        return dict([(key, perms) for (key, _, perms) in cls.ROLES])


class Permissions(DocumentSchema):

    def has(self, permission, data=None):
        if data:
            return getattr(self, permission)(data)
        else:
            return getattr(self, permission)

    def set(self, permission, value, data=None):
        if self.has(permission, data) == value:
            return
        if data:
            getattr(self, permission)(data, value)
        else:
            setattr(self, permission, value)

    def _getattr(self, name):
        a = getattr(self, name)
        if isinstance(a, list):
            a = set(a)
        return a

    def _setattr(self, name, value):
        if isinstance(value, set):
            value = list(value)
        setattr(self, name, value)

    def __or__(self, other):
        permissions = type(self)()
        for name in permissions.properties():
            permissions._setattr(name, self._getattr(name) | other._getattr(name))
        return permissions

    def __eq__(self, other):
        for name in self.properties():
            if self._getattr(name) != other._getattr(name):
                return False
        return True

class AllOrSomePermission(object):
    def __init__(self, all_attr, some_attr):
        self.all_attr = all_attr
        self.some_attr = some_attr

    def __get__(self, instance, owner):
        return functools.partial(self._fn, instance)

    def _fn(self, instance, item, value=None):
        if value is None:
            return getattr(instance, self.all_attr) or item in getattr(instance, self.some_attr)
        else:
            if value:
                if item not in getattr(instance, self.some_attr):
                    updated_list = getattr(instance, self.some_attr).append(item)
                    setattr(instance, self.some_attr, updated_list)
            else:
                try:
                    updated_list = getattr(instance, self.some_attr).remove(item)
                    setattr(instance, self.some_attr, updated_list)
                except ValueError:
                    pass

class DomainPermissions(Permissions):

    edit_web_users = BooleanProperty(default=False)
    edit_commcare_users = BooleanProperty(default=False)
    edit_data = BooleanProperty(default=False)
    edit_apps = BooleanProperty(default=False)

    view_reports = BooleanProperty(default=False)
    view_report_list = StringListProperty(default=[])

    view_report = AllOrSomePermission('view_reports', 'view_report_list')


    @classmethod
    def max(cls):
        return cls(
            edit_web_users=True,
            edit_commcare_users=True,
            edit_data=True,
            edit_apps=True,
            view_reports=True,
        )


class OrganizationPermissions(Permissions):


    edit_projects = BooleanProperty(default=False)
    edit_members = BooleanProperty(default=False)
    edit_teams = BooleanProperty(default=False)

    view_teams = BooleanProperty(default=False)
    view_team_list = StringListProperty(default=[])

    view_team = AllOrSomePermission('view_teams', 'view_team_list')


    @classmethod
    def max(cls):
        return cls(
            edit_projects = True,
            edit_members = True,
            edit_teams = True,
            view_teams = True
        )

class UserRole(Document):
    name = StringProperty()

    def get_qualified_id(self):
        return 'user-role:%s' % self.get_id

    @classmethod
    def get_or_create_with_permissions(cls, subject, permissions, name=None):
        permissions = cls.wrap_permissions(permissions)
        roles = cls.by_subject(subject)
        # try to get a matching role from the db
        for role in roles:
            role_permissions = cls.wrap_permissions(role.permissions)
            if role_permissions == permissions:
                return role
        # otherwise create it
        def get_name():
            if name:
                return name
            else:
                return cls.get_default_role_name(permissions)

        if issubclass(cls, DomainUserRole):
            role = cls(domain=subject, permissions=permissions, name=get_name())
        elif issubclass(cls, OrganizationUserRole):
            role = cls(organization=subject, permissions=permissions, name=get_name())
        role.save()
        return role

    @classmethod
    def wrap_permissions(cls, permissions):
        if isinstance(permissions, dict):
            permissions = DomainPermissions.wrap(permissions)
        return permissions

    @classmethod
    def by_subject(cls, domain):
        return cls.view('users/roles_by_domain',
            key=domain,
            include_docs=True,
            reduce=False,
        )


DOMAIN_PERMISSIONS_PRESETS = {
    'edit-apps': {'name': 'App Editor', 'permissions': DomainPermissions(edit_apps=True, view_reports=True)},
    'field-implementer': {'name': 'Field Implementer', 'permissions': DomainPermissions(edit_commcare_users=True, view_reports=True)},
    'read-only': {'name': 'Read Only', 'permissions': DomainPermissions(view_reports=True)},
    'no-permissions': {'name': 'Read Only', 'permissions': DomainPermissions(view_reports=True)},
}

ORGANIZATION_PERMISSIONS_PRESETS = {
    'member': {'name': 'Member', 'permissions': OrganizationPermissions(edit_members=True)},
    'project-manager': {'name': 'Project Manager', 'permissions': OrganizationPermissions(edit_members=True, edit_projects=True)},
    'team-manaer': {'name': 'Team Manager', 'permissions': OrganizationPermissions(edit_members=True, edit_teams=True, view_teams=True)},
    'nonmember': {'name': 'NonMember', 'permissions': OrganizationPermissions()},
}

class DomainUserRole(UserRole):
    domain = StringProperty()
    permissions = SchemaProperty(DomainPermissions)

    #this is in UserRole because all legacy roles will be for domains
#    @classmethod
#    def by_subject(cls, domain):
#        return cls.view('users/roles_by_domain',
#            key=domain,
#            include_docs=True,
#            reduce=False,
#        )

    @classmethod
    def get_default(cls, domain=None):
        return cls(permissions=DomainPermissions(), domain=domain, name=None)

    @classmethod
    def role_choices(cls, domain):
        return [(role.get_qualified_id(), role.name or '(No Name)') for role in [AdminDomainUserRole(subject=domain)] + list(cls.by_subject(domain))]

    @classmethod
    def commcareuser_role_choices(cls, domain):
        return [('none','(none)')] + [(role.get_qualified_id(), role.name or '(No Name)') for role in list(cls.by_subject(domain))]

    @classmethod
    def init_with_presets(cls, subject):
        cls.get_or_create_with_permissions(subject, DomainPermissions(edit_apps=True, view_reports=True), 'App Editor')
        cls.get_or_create_with_permissions(subject, DomainPermissions(edit_commcare_users=True, view_reports=True), 'Field Implementer')
        cls.get_or_create_with_permissions(subject, DomainPermissions(view_reports=True), 'Read Only')

        #this is in UserRole because all legacy roles will be for domains
    #    @classmethod
#    def wrap_permissions(cls, permissions):
#        permissions = DomainPermissions.wrap(permissions)
#        return permissions

    @classmethod
    def get_default_role_name(cls, permissions):
        if permissions == DomainPermissions():
            return "Read Only (No Reports)"
        elif permissions == DomainPermissions(edit_apps=True, view_reports=True):
            return "App Editor"
        elif permissions == DomainPermissions(view_reports=True):
            return "Read Only"
        elif permissions == DomainPermissions(edit_commcare_users=True, view_reports=True):
            return "Field Implementer"


class OrganizationUserRole(UserRole):
    organization = StringProperty()
    permissions = SchemaProperty(OrganizationPermissions)


    @classmethod
    def by_subject(cls, org):
        return cls.view('users/roles_by_organization',
        key=org,
        include_docs=True,
        reduce=False,
        )

    @classmethod
    def get_default(cls, organization=None):
        return cls(permissions=OrganizationPermissions(), organization=organization, name=None)

    @classmethod
    def role_choices(cls, organization):
        return [(role.get_qualified_id(), role.name or '(No Name)') for role in [AdminOrganizationUserRole(subject=organization)] + list(cls.by_subject(organization))]


    @classmethod
    def init_with_presets(cls, subject):
        cls.get_or_create_with_permissions(subject, OrganizationPermissions(edit_members=True), 'Member')
        cls.get_or_create_with_permissions(subject, OrganizationPermissions(edit_members=True, edit_projects=True, view_teams=True), 'Project Manager')
        cls.get_or_create_with_permissions(subject, OrganizationPermissions(edit_members=True, edit_teams=True), 'Team Manager')

    @classmethod
    def wrap_permissions(cls, permissions):
        if isinstance(permissions, dict):
            permissions = OrganizationPermissions.wrap(permissions)
        return permissions

    @classmethod
    def get_default_role_name(cls, permissions):
        if permissions == OrganizationPermissions():
            return "NonMember"
        elif permissions == OrganizationPermissions(edit_members=True):
            return "Member"
        elif permissions == OrganizationPermissions(edit_members=True, edit_projects=True):
            return "Project Manager"
        elif permissions == OrganizationPermissions(edit_members=True, edit_teams=True):
            return "Team Manager"

class AdminDomainUserRole(DomainUserRole):
    def __init__(self, subject):
        super(AdminDomainUserRole, self).__init__(domain=subject, name='Admin', permissions=DomainPermissions.max())
    def get_qualified_id(self):
        return 'admin'

class AdminOrganizationUserRole(OrganizationUserRole):
    def __init__(self, subject):
        super(AdminOrganizationUserRole, self).__init__(organization=subject, name='Admin', permissions=OrganizationPermissions.max())
    def get_qualified_id(self):
        return 'admin'

class DomainMembershipError(Exception):
    pass

class OrganizationMembershipError(Exception):
    pass

class Membership(DocumentSchema):
    is_admin = BooleanProperty(default=False)
    # old permissions
    # permissions = StringListProperty()
    # permissions_data = DictProperty()
    last_login = DateTimeProperty()
    date_joined = DateTimeProperty()
    timezone = StringProperty(default=getattr(settings, "TIME_ZONE", "UTC"))
    override_global_tz = BooleanProperty(default=False)
    subject = StringProperty()

    #legacy variable
    domain = StringProperty()

    role_id = StringProperty()


    @property
    def permissions(self):
        if self.role:
            return self.role.permissions
        else:
            return self.classes.Permissions()


    @property
    def role(self):
        if self.is_admin:
            return self.classes.AdminUserRole(self.subject or self.domain)
        elif self.role_id:
            return self.classes.UserRole.get(self.role_id)
        else:
            return None


    def has_permission(self, permission, data=None):
        return self.is_admin or self.classes.UserRole.wrap_permissions(self.permissions).has(permission, data)

    class Meta:
        app_label = 'users'

class DomainMembership(Membership):
    """
    Each user can have multiple accounts on the
    web domain. This is primarily for Dimagi staff.
    """
#    @property
#    def domain(self):
#        return self.subject

    class classes(object):
        UserRole = DomainUserRole
        AdminUserRole = AdminDomainUserRole
        Permissions = DomainPermissions


    @classmethod
    def wrap(cls, data):
        # Do a just-in-time conversion of old permissions
        old_permissions = data.get('permissions')
        if old_permissions is not None:
            del data['permissions']
            if data.has_key('permissions_data'):
                permissions_data = data['permissions_data']
                del data['permissions_data']
            else:
                permissions_data = {}
            if not data['is_admin']:
                view_report_list = permissions_data.get('view-report')
                custom_permissions = {}
                for old_permission in old_permissions:
                    if old_permission == 'view-report':
                        continue
                    new_permission = OldPermissions.to_new(old_permission)
                    custom_permissions[new_permission] = True

                if not view_report_list:
                    # Anyone whose report permissions haven't been explicitly taken away/reduced
                    # should be able to see reports by default
                    custom_permissions['view_reports'] = True
                else:
                    custom_permissions['view_report_list'] = view_report_list


                self = super(DomainMembership, cls).wrap(data)
                self.role_id = UserRole.get_or_create_with_permissions(self.domain, custom_permissions).get_id
                return self
        return super(DomainMembership, cls).wrap(data)


    def viewable_reports(self):
        return self.permissions.view_report_list


class OrganizationMembership(Membership):

    class classes(object):
        UserRole = OrganizationUserRole
        AdminUserRole = AdminOrganizationUserRole
        Permissions = OrganizationPermissions

    def viewable_teams(self):
        return self.permissions.view_team_list

class CustomDomainMembership(DomainMembership):
    custom_role = SchemaProperty(DomainUserRole)

    @property
    def role(self):
        if self.is_admin:
            return AdminDomainUserRole(self.domain)
        else:
            return self.custom_role

    def set_permission(self, permission, value, data=None):
        self.custom_role.domain = self.domain
        self.custom_role.permissions.set(permission, value, data)

class MembershipManager(object):
    #item_class must have fields: name, is_active, date_created
    def __init__(self, items, item_memberships, item_label, item_membership_label, item_class, item_membership_class, item_user_role, current_item, admin_role_class, item_membership_error_class, permission_presets):
        self.items = items
        self.item_memberships = item_memberships
        self.item_label = item_label
        self.item_membership_label = item_membership_label
        self.item_class = item_class
        self.item_membership_class = item_membership_class
        self.item_user_role = item_user_role
        self.current_item = current_item
        self.admin_role_class = admin_role_class
        self.item_membership_error_class = item_membership_error_class
        self.permission_presets = permission_presets

    def is_global_admin(self):
        # subclasses to override if they want this functionality
        return False

    def get_membership(self, instance, item):
        item_membership = None
        try:
            for i in getattr(instance, self.item_memberships):
                if not i.subject:
                    i.subject = i.domain
                if i.subject == item:
                    item_membership = i
                    if item not in getattr(instance, self.items):
                        raise CouchUser.Inconsistent(getattr(instance, self.item_label) + "'%s' is in " % item + getattr(instance, self.item_membership_label) +  "but not domains")

            if not item_membership and item in getattr(instance, self.items):
                raise CouchUser.Inconsistent(getattr(instance, self.item_label) + " '%s' is in " % item + getattr(instance, self.item_label) + " but not in " + getattr(instance, self.item_membership_label))
        except CouchUser.Inconsistent as e:
            logging.warning(e)
            consistent_list =  [i.subject or i.domain for i in getattr(instance, self.item_memberships)]
            setattr(instance, self.items, consistent_list)
        return item_membership

    def add_membership(self, instance, item, **kwargs):
        for i in getattr(instance, self.item_memberships):
            if not i.subject:
                i.subject = i.domain
            if i.subject == item:
                if item not in getattr(instance, self.items):
                    raise CouchUser.Inconsistent(getattr(instance, self.item_label) + "'%s' is in " + getattr(instance, self.item_membership_label) +  "but not domains" % item)
                return
        item_obj = getattr(instance, self.item_class).get_by_name(item)
        if not item_obj:
            item_obj = getattr(instance, self.item_class)(is_active=True, name=item, date_created=datetime.utcnow())
            item_obj.save()

        if kwargs.get('subject'):
            if kwargs.get('timezone'):
                item_membership = getattr(instance, self.item_membership_class)(**kwargs)
            else:
                item_membership = getattr(instance, self.item_membership_class)(
                                                timezone=item_obj.default_timezone,
                                                **kwargs)
        else:
            if kwargs.get('timezone'):
                item_membership = getattr(instance, self.item_membership_class)(subject = item)
            else:
                item_membership = getattr(instance, self.item_membership_class)(subject = item,
                                                timezone=item_obj.default_timezone)

        membership_list = getattr(instance, self.item_memberships)
        membership_list.append(item_membership)
        item_list = getattr(instance, self.items)
        item_list.append(item_membership.subject or item_membership.domain or item)
        setattr(instance, self.item_memberships, membership_list)
        setattr(instance, self.items, item_list)

    # right now, only domain memberships can use the property create_record
    def delete_membership(self, instance, item, create_record=False):
        record = ''
        for i, item_membership in enumerate(getattr(instance, self.item_memberships)):
            if not item_membership.subject:
                item_membership.subject = item_membership.domain
            if item_membership.subject == item:
                if create_record:
                    record = RemoveWebUserRecord(
                        domain=item,
                        user_id=instance.user_id,
                        domain_membership=item_membership,
                        )
                membership_list = getattr(instance, self.item_memberships)
                del membership_list[i]
                setattr(instance, self.item_memberships, membership_list)
                break
        for i, item_name in enumerate(getattr(instance, self.items)):
            if item_name == item:
                item_list = getattr(instance, self.items)
                del item_list[i]
                setattr(instance, self.items, item_list)
                break
        if create_record:
            if record:
                record.save()
                return record
            else:
                return 'error'
    def is_admin(self, instance, item=None):
        if not item:
            # hack for template
            #only for domains
            if hasattr(instance, self.current_item):
                # this is a hack needed because we can't pass parameters from views
                item = getattr(instance, self.current_item)
            else:
                return False  # no domain, no admin
        if instance.is_global_admin():
            return True
        item_membership = self.get_membership(instance, item)
        if item_membership:
            return item_membership.is_admin
        else:
            return False


    def get_items(self, instance):
        items = [item_memberships.subject or item_memberships.domain for item_memberships in getattr(instance, self.item_memberships)]
        if set(items) == set(getattr(instance, self.items)):
            return items
        else:
            raise CouchUser.Inconsistent("domains and domain_memberships out of sync")



    def has_permission(self, instance, item, permission, data=None, collective=False):
        # is_admin is the same as having all the permissions set
        if instance.is_global_admin():
            return True
        elif self.is_admin(instance, item):
            return True

        if collective:
            item_membership = instance.get_membership(item)
        else:
            item_membership = self.get_membership(instance, item)

        if item_membership:
            return item_membership.has_permission(permission, data)
        else:
            return False

    def is_member_of(self, instance, item_qs):
        try:
            return item_qs.name in self.get_items(instance) or instance.is_global_admin()
        except Exception:
            return item_qs in self.get_items(instance) or instance.is_global_admin()

    def get_role(self, instance, item=None):
        """
        Get the role object for this user

        """
        if item is None:
            # default to current_domain for django templates
            item = getattr(instance, self.current_item)

        if instance.is_global_admin():
            return getattr(instance, self.admin_role_class)(subject=item)
        if self.is_member_of(instance, item):
            return self.get_membership(instance, item).role
        else:
            raise getattr(instance, self.item_membership_error_class)()

    def set_role(self, instance, item, role_qualified_id):
        """
        role_qualified_id is either 'admin' 'user-role:[id]'
        """
        item_membership = self.get_membership(instance, item)
        item_membership.is_admin = False
        if role_qualified_id == "admin":
            item_membership.is_admin = True
        elif role_qualified_id.startswith('user-role:'):
            item_membership.role_id = role_qualified_id[len('user-role:'):]
        elif role_qualified_id in getattr(instance, self.permission_presets):
            preset = getattr(instance, self.permission_presets)[role_qualified_id]
            item_membership.role_id = getattr(instance, self.item_user_role).get_or_create_with_permissions(item, preset['permissions'], preset['name']).get_id
        else:
            raise Exception("role_qualified_id is %r" % role_qualified_id)


    def role_label(self, instance, item=None, collective=False):
        if not item:
            try:
                item = getattr(instance, self.current_item)
            except (AttributeError, KeyError):
                return None
        try:
            if collective:
                return instance.get_role(item=item).name
            else:
                return self.get_role(instance, item=item).name
        except TypeError:
            return "Unknown User"
        except getattr(instance, self.item_membership_error_class):
            return "Unauthorized User"
        except Exception:
            return None


class DomainAuthorizableMixin(DocumentSchema):
    domains = StringListProperty()
    domain_memberships = SchemaListProperty(DomainMembership)
    domain_label = 'domain'
    domain_membership_label = 'domain membership'
    domain_class = Domain
    domain_membership_class = DomainMembership
    domain_user_role = DomainUserRole
    domain_admin_role_class = AdminDomainUserRole
    domain_membership_error_class = DomainMembershipError

    @property
    def domain_permission_presets(self):
        return DOMAIN_PERMISSIONS_PRESETS

    domain_manager = MembershipManager(items='domains', item_memberships='domain_memberships', item_label='domain',
        item_membership_label='domain membership', item_class=Domain, item_membership_class=DomainMembership, item_user_role=DomainUserRole,
        current_item='current_domain', admin_role_class=AdminDomainUserRole, item_membership_error_class=DomainMembershipError,
        permission_presets='domain_permission_presets')

    def is_global_admin(self):
        # subclasses to override if they want this functionality
        return False

    def get_domain_membership(self, domain):
        return self.domain_manager.get_membership(self, domain)

    def add_domain_membership(self, domain, **kwargs):
        return self.domain_manager.add_membership(self, domain, **kwargs)

    def delete_domain_membership(self, domain, create_record=False):
        return self.domain_manager.delete_membership(self, domain, create_record=create_record)

    def is_domain_admin(self, domain=None):
        return self.domain_manager.is_admin(self, item=domain)

    def get_domains(self):
        return self.domain_manager.get_items(self)

    def has_permission(self, domain, permission, data=None):
        return self.domain_manager.has_permission(self, domain, permission, data=data, collective=True)

    def is_member_of(self, domain_qs):
        return self.domain_manager.is_member_of(self, domain_qs)

    def get_role(self, item=None, domain=None):
        """
        Get the role object for this user

        """
        if not item:
            item = domain
        return self.domain_manager.get_role(self, item=item)

    def set_role(self, domain, role_qualified_id):
        """
        role_qualified_id is either 'admin' 'user-role:[id]'
        """
        return self.domain_manager.set_role(self, domain, role_qualified_id)

    def role_label(self, item=None):
        return self.domain_manager.role_label(self, item=item, collective=True)


from corehq.apps.orgs.models import Organization
class OrganizationAuthorizableMixin(DocumentSchema):
    organizations = StringListProperty()
    organization_memberships = SchemaListProperty(OrganizationMembership)
    organization_label = 'organization'
    organization_membership_label = 'organization membership'
    organization_class = Organization
    organization_membership_class = OrganizationMembership
    organization_user_role = OrganizationUserRole
    organization_admin_role_class = AdminOrganizationUserRole
    organization_membership_error_class = OrganizationMembershipError

    @property
    def organization_permission_presets(self):
        return ORGANIZATION_PERMISSIONS_PRESETS

    organization_manager = MembershipManager(items='organizations', item_memberships='organization_memberships', item_label='organization_label',
        item_membership_label='organization_membership_label', item_class='organization_class', item_membership_class='organization_membership_class', item_user_role='organization_user_role',
        current_item='current_organization', admin_role_class='organization_admin_role_class', item_membership_error_class='organization_membership_error_class',
        permission_presets='organization_permission_presets')

    def get_role(self, item=None, organization=None):
        """
        Get the role object for this user

        """
        if not item:
            item = organization
        return self.organization_manager.get_role(self, item=item)


class LowercaseStringProperty(StringProperty):
    """
    Make sure that the string is always lowercase'd
    """
    def _adjust_value(self, value):
        if value is not None:
            return value.lower()

#    def __set__(self, instance, value):
#        return super(LowercaseStringProperty, self).__set__(instance, self._adjust_value(value))

#    def __property_init__(self, instance, value):
#        return super(LowercaseStringProperty, self).__property_init__(instance, self._adjust_value(value))

    def to_json(self, value):
        return super(LowercaseStringProperty, self).to_json(self._adjust_value(value))



class DjangoUserMixin(DocumentSchema):
    username = LowercaseStringProperty()
    first_name = StringProperty()
    last_name = StringProperty()
    email = LowercaseStringProperty()
    password = StringProperty()
    is_staff = BooleanProperty()
    is_active = BooleanProperty()
    is_superuser = BooleanProperty()
    last_login = DateTimeProperty()
    date_joined = DateTimeProperty()

    ATTRS = (
        'username',
        'first_name',
        'last_name',
        'email',
        'password',
        'is_staff',
        'is_active',
        'is_superuser',
        'last_login',
        'date_joined',
    )

    def set_password(self, raw_password):
        dummy = User()
        dummy.set_password(raw_password)
        self.password = dummy.password

    def check_password(self, password):
        """ Currently just for debugging"""
        dummy = User()
        dummy.password = self.password
        return dummy.check_password(password)

class CouchUser(Document, DjangoUserMixin, UnicodeMixIn):
    """
    A user (for web and commcare)
    """
    base_doc = 'CouchUser'
    device_ids = ListProperty()
    phone_numbers = ListProperty()
    created_on = DateTimeProperty()
#    For now, 'status' is things like:
#        ('auto_created',     'Automatically created from form submission.'),
#        ('phone_registered', 'Registered from phone'),
#        ('site_edited',     'Manually added or edited from the HQ website.'),
    status = StringProperty()
    language = StringProperty()

    _user = None
    _user_checked = False

    class AccountTypeError(Exception):
        pass

    class Inconsistent(Exception):
        pass

    class InvalidID(Exception):
        pass

    @property
    def raw_username(self):
        if self.doc_type == "CommCareUser":
            return self.username.split("@")[0]
        else:
            return self.username

    def html_username(self):
        username = self.username
        if '@' in username:
            html = "<span class='user_username'>%s</span><span class='user_domainname'>@%s</span>" % \
                   tuple(username.split('@'))
        else:
            html = "<span class='user_username'>%s</span>" % username
        return html

    @property
    def userID(self):
        return self._id

    user_id = userID

    class Meta:
        app_label = 'users'

    def __unicode__(self):
        return "%s %s" % (self.__class__.__name__, self.get_id)

    def get_email(self):
        return self.email

    @property
    def full_name(self):
        return "%s %s" % (self.first_name, self.last_name)

    formatted_name = full_name
    name = full_name

    def set_full_name(self, full_name):
        data = full_name.split()
        self.first_name = data.pop(0)
        self.last_name = ' '.join(data)

    def get_scheduled_reports(self):
        return ReportNotification.view("reports/user_notifications", key=self.user_id, include_docs=True).all()

    def delete(self):
        try:
            user = self.get_django_user()
            user.delete()
        except User.DoesNotExist:
            pass
        super(CouchUser, self).delete() # Call the "real" delete() method.

    def get_django_user(self):
        return User.objects.get(username__iexact=self.username)

    def add_phone_number(self, phone_number, default=False, **kwargs):
        """ Don't add phone numbers if they already exist """
        if not isinstance(phone_number, basestring):
            phone_number = str(phone_number)
        self.phone_numbers = _add_to_list(self.phone_numbers, phone_number, default)

    @property
    def default_phone_number(self):
        return _get_default(self.phone_numbers)
    phone_number = default_phone_number

    @property
    def couch_id(self):
        return self._id

    # Couch view wrappers
    @classmethod
    def all(cls):
        return CouchUser.view("users/by_username", include_docs=True)

    @classmethod
    def by_domain(cls, domain, is_active=True):
        flag = "active" if is_active else "inactive"
        if cls.__name__ == "CouchUser":
            key = [flag, domain]
        else:
            key = [flag, domain, cls.__name__]
        return cls.view("users/by_domain",
            reduce=False,
            startkey=key,
            endkey=key + [{}],
            include_docs=True,
        ).all()

    @classmethod
    def phone_users_by_domain(cls, domain):
        return CouchUser.view("users/phone_users_by_domain",
            startkey=[domain],
            endkey=[domain, {}],
            include_docs=True,
        )

    def is_previewer(self):
        try:
            from django.conf.settings import PREVIEWER_RE
        except ImportError:
            return self.is_superuser
        else:
            return self.is_superuser or re.compile(PREVIEWER_RE).match(self.username)

    # for synching
    def sync_from_django_user(self, django_user):
        if not django_user:
            django_user = self.get_django_user()
        for attr in DjangoUserMixin.ATTRS:
            setattr(self, attr, getattr(django_user, attr))

    def sync_to_django_user(self):
        try:
            django_user = self.get_django_user()
        except User.DoesNotExist:
            django_user = User(username=self.username)
        for attr in DjangoUserMixin.ATTRS:
            setattr(django_user, attr, getattr(self, attr))
        django_user.DO_NOT_SAVE_COUCH_USER= True
        return django_user

    def sync_from_old_couch_user(self, old_couch_user):
        login = old_couch_user.default_account.login
        self.sync_from_django_user(login)

        for attr in (
            'device_ids',
            'phone_numbers',
            'created_on',
            'status',
        ):
            setattr(self, attr, getattr(old_couch_user, attr))

    @classmethod
    def from_old_couch_user(cls, old_couch_user, copy_id=True):

        if old_couch_user.account_type == "WebAccount":
            couch_user = WebUser()
        else:
            couch_user = CommCareUser()

        couch_user.sync_from_old_couch_user(old_couch_user)

        if old_couch_user.email:
            couch_user.email = old_couch_user.email

        if copy_id:
            couch_user._id = old_couch_user.default_account.login_id

        return couch_user

    @classmethod
    def wrap_correctly(cls, source):
        if source.get('doc_type') == 'CouchUser' and \
                source.has_key('commcare_accounts') and \
                source.has_key('web_accounts'):
            from . import old_couch_user_models
            user_id = old_couch_user_models.CouchUser.wrap(source).default_account.login_id
            return cls.get_by_user_id(user_id)
        else:
            return {
                'WebUser': WebUser,
                'CommCareUser': CommCareUser,
                'FakeUser': FakeUser,
            }[source['doc_type']].wrap(source)

    @classmethod
    def get_by_username(cls, username):
        result = get_db().view('users/by_username', key=username, include_docs=True).one()
        if result:
            return cls.wrap_correctly(result['doc'])
        else:
            return None

    @classmethod
    def get_by_default_phone(cls, phone_number):
        result = get_db().view('users/by_default_phone', key=phone_number, include_docs=True).one()
        if result:
            return cls.wrap_correctly(result['doc'])
        else:
            return None


    def is_member_of(self, domain_qs):
        """
        takes either a domain name or a domain object and returns whether the user is part of that domain
        either natively or through a team
        """
        try:
            return domain_qs.name in self.get_domains() or self.is_global_admin()
        except Exception:
            return domain_qs in self.get_domains() or self.is_global_admin()


    @classmethod
    def get_by_user_id(cls, userID, domain=None):
        """
        if domain is given, checks to make sure the user is a member of that domain
        returns None if there's no user found or if the domain check fails

        """
        try:
            couch_user = cls.wrap_correctly(get_db().get(userID))
        except ResourceNotFound:
            return None
        if couch_user.doc_type != cls.__name__ and cls.__name__ != "CouchUser":
            raise CouchUser.AccountTypeError()
        if domain:
            if not couch_user.is_member_of(domain):
                return None
        return couch_user

    @classmethod
    def from_django_user(cls, django_user):
        return cls.get_by_username(django_user.username)

    @classmethod
    def create(cls, domain, username, password, email=None, uuid='', date='', **kwargs):
        django_user = create_user(username, password=password, email=email)
        if uuid:
            if not re.match(r'[\w-]+', uuid):
                raise cls.InvalidID('invalid id %r' % uuid)
            couch_user = cls(_id=uuid)
        else:
            couch_user = cls()

        if date:
            couch_user.created_on = force_to_datetime(date)
        else:
            couch_user.created_on = datetime.utcnow()
        couch_user.sync_from_django_user(django_user)
        return couch_user

    def change_username(self, username):
        if username == self.username:
            return

        if User.objects.filter(username=username).exists():
            raise self.Inconsistent("User with username %s already exists" % self.username)

        django_user = self.get_django_user()
        django_user.DO_NOT_SAVE_COUCH_USER = True
        django_user.username = username
        django_user.save()
        self.username = username
        self.save()


    def save(self, **params):
        # test no username conflict
        by_username = get_db().view('users/by_username', key=self.username).one()
        if by_username and by_username['id'] != self._id:
            raise self.Inconsistent("CouchUser with username %s already exists" % self.username)

        super(CouchUser, self).save(**params)
        if not self.base_doc.endswith(DELETED_SUFFIX):
            django_user = self.sync_to_django_user()
            django_user.save()


    @classmethod
    def django_user_post_save_signal(cls, sender, django_user, created, **kwargs):
        if hasattr(django_user, 'DO_NOT_SAVE_COUCH_USER'):
            del django_user.DO_NOT_SAVE_COUCH_USER
        else:
            couch_user = cls.from_django_user(django_user)
            if couch_user:
                couch_user.sync_from_django_user(django_user)
                # avoid triggering cyclical sync
                super(CouchUser, couch_user).save()

    def is_deleted(self):
        return self.base_doc.endswith(DELETED_SUFFIX)

    def get_viewable_reports(self, domain=None, name=True):
        domain = domain or self.current_domain
        try:
            if self.is_commcare_user():
                role = self.get_role(domain)
                if role is None:
                    models = []
                else:
                    models = role.permissions.view_report_list
            else:
                models = self.get_domain_membership(domain).viewable_reports()
            
            if name:
                return [to_function(m).name for m in models]
            else:
                return models
        except AttributeError:
            return []

    def has_permission(self, domain, permission, data=None):
        """To be overridden by subclasses"""
        return False

    def __getattr__(self, item):
        if item.startswith('can_'):
            perm = item[len('can_'):]
            if perm:
                def fn(domain=None, data=None):
                    domain = domain or self.current_domain
                    print domain, perm, data
                    print self.has_permission(domain, perm, data)
                    return self.has_permission(domain, perm, data)
                fn.__name__ = item
                return fn
        return super(CouchUser, self).__getattr__(item)


class CommCareUser(CouchUser, CommCareMobileContactMixin):

    domain = StringProperty()
    registering_device_id = StringProperty()
    user_data = DictProperty()
    role_id = StringProperty()

    def sync_from_old_couch_user(self, old_couch_user):
        super(CommCareUser, self).sync_from_old_couch_user(old_couch_user)
        self.domain                 = normalize_domain_name(old_couch_user.default_account.domain)
        self.registering_device_id  = old_couch_user.default_account.registering_device_id
        self.user_data              = old_couch_user.default_account.user_data

    @classmethod
    def create(cls, domain, username, password, email=None, uuid='', date='', **kwargs):
        """
        used to be a function called `create_hq_user_from_commcare_registration_info`

        """
        commcare_user = super(CommCareUser, cls).create(domain, username, password, email, uuid, date, **kwargs)

        device_id = kwargs.get('device_id', '')
        user_data = kwargs.get('user_data', {})

        # populate the couch user
        commcare_user.domain = domain
        commcare_user.device_ids = [device_id]
        commcare_user.registering_device_id = device_id
        commcare_user.user_data = user_data

        commcare_user.save()

        return commcare_user

    @property
    def filter_flag(self):
        return HQUserType.REGISTERED

    @property
    def username_in_report(self):
        if (self.first_name == '' and self.last_name == ''):
            return self.raw_username
        return self.full_name

    @classmethod
    def create_or_update_from_xform(cls, xform):
        # if we have 1,000,000 users with the same name in a domain
        # then we have bigger problems then duplicate user accounts
        MAX_DUPLICATE_USERS = 1000000

        def create_or_update_safe(username, password, uuid, date, registering_phone_id, domain, user_data, **kwargs):
            # check for uuid conflicts, if one exists, respond with the already-created user
            conflicting_user = CommCareUser.get_by_user_id(uuid)

            # we need to check for username conflicts, other issues
            # and make sure we send the appropriate conflict response to the phone
            try:
                username = normalize_username(username, domain)
            except ValidationError:
                raise Exception("Username (%s) is invalid: valid characters include [a-z], "
                                "[0-9], period, underscore, and single quote" % username)

            if conflicting_user:
                # try to update. If there are username conflicts, we have to resolve them
                if conflicting_user.domain != domain:
                    raise Exception("Found a conflicting user in another domain. This is not allowed!")

                saved = False
                to_append = 2
                prefix, suffix = username.split("@")
                while not saved and to_append < MAX_DUPLICATE_USERS:
                    try:
                        conflicting_user.change_username(username)
                        conflicting_user.password = password
                        conflicting_user.date = date
                        conflicting_user.device_id = registering_phone_id
                        conflicting_user.user_data = user_data
                        conflicting_user.save()
                        saved = True
                    except CouchUser.Inconsistent:
                        username = "%(pref)s%(count)s@%(suff)s" % {
                                     "pref": prefix, "count": to_append,
                                     "suff": suffix}
                        to_append = to_append + 1
                if not saved:
                    raise Exception("There are over 1,000,000 users with that base name in your domain. REALLY?!? REALLY?!?!")
                return (conflicting_user, False)

            try:
                User.objects.get(username=username)
            except User.DoesNotExist:
                # Desired outcome
                pass
            else:
                # Come up with a suitable username
                prefix, suffix = username.split("@")
                username = get_unique_value(User.objects, "username", prefix, sep="", suffix="@%s" % suffix)
            couch_user = cls.create(domain, username, password,
                uuid=uuid,
                device_id=registering_phone_id,
                date=date,
                user_data=user_data
            )
            return (couch_user, True)

        # will raise TypeError if xform.form doesn't have all the necessary params
        return create_or_update_safe(
            domain=xform.domain,
            user_data=user_data_from_registration_form(xform),
            **dict([(arg, xform.form[arg]) for arg in (
                'username',
                'password',
                'uuid',
                'date',
                'registering_phone_id'
            )])
        )

    @classmethod
    def cannot_share(cls, domain):
        return [user for user in cls.by_domain(domain) if len(user.get_case_sharing_groups()) != 1]

    def is_commcare_user(self):
        return True

    def is_web_user(self):
        return False

    def get_domains(self):
        return [self.domain]

    def add_commcare_account(self, domain, device_id, user_data=None):
        """
        Adds a commcare account to this.
        """
        if self.domain and self.domain != domain:
            raise self.Inconsistent("Tried to reinitialize commcare account to a different domain")
        self.domain = domain
        self.registering_device_id = device_id
        self.user_data = user_data or {}
        self.add_device_id(device_id=device_id)

    def add_device_id(self, device_id, default=False, **kwargs):
        """ Don't add phone devices if they already exist """
        self.device_ids = _add_to_list(self.device_ids, device_id, default)

    def to_casexml_user(self):
        user = CaseXMLUser(user_id=self.userID,
                           username=self.raw_username,
                           password=self.password,
                           date_joined=self.date_joined,
                           user_data=self.user_data)

        def get_owner_ids():
            return self.get_owner_ids()
        user.get_owner_ids = get_owner_ids
        user._hq_user = self # don't tell anyone that we snuck this here
        return user

    def get_forms(self, deleted=False, wrap=True):
        if deleted:
            view_name = 'users/deleted_forms_by_user'
        else:
            view_name = 'couchforms/by_user'

        return XFormInstance.view(view_name,
            startkey=[self.user_id],
            endkey=[self.user_id, {}],
            reduce=False,
            include_docs=wrap,
            wrapper=None if wrap else lambda x: x['id']
        )

    @property
    def form_count(self):
        result = XFormInstance.view('couchforms/by_user',
            startkey=[self.user_id],
            endkey=[self.user_id, {}],
                group_level=0
        ).one()
        if result:
            return result['value']
        else:
            return 0

    def get_cases(self, deleted=False, last_submitter=False):
        if deleted:
            view_name = 'users/deleted_cases_by_user'
        elif last_submitter:
            view_name = 'case/by_user'
        else:
            view_name = 'case/by_owner'

        return CommCareCase.view(view_name,
            startkey=[self.user_id],
            endkey=[self.user_id, {}],
            reduce=False,
            include_docs=True
        )

    @property
    def case_count(self):
        result = CommCareCase.view('case/by_user',
            startkey=[self.user_id],
            endkey=[self.user_id, {}],
            group_level=0
        ).one()
        if result:
            return result['value']
        else:
            return 0

    def get_owner_ids(self):
        from corehq.apps.groups.models import Group

        owner_ids = [self.user_id]
        owner_ids.extend(Group.by_user(self, wrap=False))

        return owner_ids

    def retire(self):
        suffix = DELETED_SUFFIX
        deletion_id = random_hex()
        # doc_type remains the same, since the views use base_doc instead
        if not self.base_doc.endswith(suffix):
            self.base_doc += suffix
            self['-deletion_id'] = deletion_id
        for form in self.get_forms():
            form.doc_type += suffix
            form['-deletion_id'] = deletion_id
            form.save()
        for case in self.get_cases():
            case.doc_type += suffix
            case['-deletion_id'] = deletion_id
            case.save()

        try:
            django_user = self.get_django_user()
        except User.DoesNotExist:
            pass
        else:
            django_user.delete()
        self.save()

    def unretire(self):
        def chop_suffix(string, suffix=DELETED_SUFFIX):
            if string.endswith(suffix):
                return string[:-len(suffix)]
            else:
                return string
        self.base_doc = chop_suffix(self.base_doc)
        for form in self.get_forms(deleted=True):
            form.doc_type = chop_suffix(form.doc_type)
            form.save()
        for case in self.get_cases(deleted=True):
            case.doc_type = chop_suffix(case.doc_type)
            case.save()
        self.save()

    def transfer_to_domain(self, domain, app_id):
        username = format_username(raw_username(self.username), domain)
        self.change_username(username)
        self.domain = domain
        for form in self.get_forms():
            form.domain = domain
            form.app_id = app_id
            form.save()
        for case in self.get_cases():
            case.domain = domain
            case.save()
        self.save()

    def get_group_fixture(self):
        return group_fixture(self.get_case_sharing_groups(), self)

    def get_case_sharing_groups(self):
        from corehq.apps.groups.models import Group
        return [group for group in Group.by_user(self) if group.case_sharing]
    def get_group_ids(self):
        from corehq.apps.groups.models import Group
        return Group.by_user(self, wrap=False)

    def get_time_zone(self):
        try:
            time_zone = self.user_data["time_zone"]
        except Exception as e:
            # Gracefully handle when user_data is None, or does not have a "time_zone" entry
            time_zone = None
        return time_zone

    def get_language_code(self):
        try:
            lang = self.user_data["language_code"]
        except Exception as e:
            # Gracefully handle when user_data is None, or does not have a "language_code" entry
            lang = None
        return lang

    def has_permission(self, domain, permission, data=None):
        if self.role_id is None:
            return False
        else:
            role = DomainUserRole.get(self.role_id)
            if role is not None:
                return role.permissions.has(permission, data)
            else:
                return False

    def get_role(self, domain=None):
        """
        Get the role object for this user
        """
        if domain is None:
            # default to current_domain for django templates
            domain = self.current_domain

        if domain != self.domain:
            return None
        elif self.role_id is None:
            return None
        else:
            return UserRole.get(self.role_id) or DomainUserRole.get(self.role_id)

    def set_role(self, domain, role_qualified_id):
        """
        role_qualified_id is either 'none' 'admin' 'user-role:[id]'
        """
        if domain != self.domain:
            raise Exception("Mobile worker does not have access to domain %s" % domain)
        else:
            # For now, only allow mobile workers to take non-admin roles
            if role_qualified_id.startswith('user-role:'):
                self.role_id = role_qualified_id[len('user-role:'):]
            elif role_qualified_id == 'none':
                self.role_id = None
            else:
                raise Exception("unexpected role_qualified_id: %r" % role_qualified_id)


class WebUser(CouchUser, DomainAuthorizableMixin, OrganizationAuthorizableMixin):

    betahack = BooleanProperty(default=False)
    teams = StringListProperty()

    #do sync and create still work?

    def sync_from_old_couch_user(self, old_couch_user):
        super(WebUser, self).sync_from_old_couch_user(old_couch_user)
        for dm in old_couch_user.web_account.domain_memberships:
            dm.subject = normalize_domain_name(dm.subject)
            self.domain_memberships.append(dm)
            self.domains.append(dm.subject)

    def is_global_admin(self):
        # override this function to pass global admin rights off to django
        return self.is_superuser

    @classmethod
    def create(cls, domain, username, password, email=None, uuid='', date='', **kwargs):
        web_user = super(WebUser, cls).create(domain, username, password, email, uuid, date, **kwargs)
        if domain:
            web_user.add_domain_membership(domain, **kwargs)
        web_user.save()
        return web_user

    def is_commcare_user(self):
        return False

    def is_web_user(self):
        return True

    def get_email(self):
        return self.email or self.username

    @property
    def projects(self):
        return map(Domain.get_by_name, self.domains)

    def get_domains(self):
        from corehq.apps.orgs.models import Team
        domains = [dm.subject or dm.domain for dm in self.domain_memberships]
        if self.teams:
            for team_name, team_id in self.teams:
                team = Team.get(team_id)
                team_domains = [dm.subject for dm in team.domain_memberships]
                for domain in team_domains:
                    if domain not in domains:
                        domains.append(domain)
        return domains

    def has_permission(self, domain, permission, data=None):
        # is_admin is the same as having all the permissions set
        from corehq.apps.orgs.models import Team
        if self.is_global_admin():
            return True
        elif self.is_domain_admin(domain):
            return True

        dm_list = list()

        dm = self.get_domain_membership(domain)
        if dm:
            dm_list.append([dm, ''])

        for team_name, team_id in self.teams:
            team = Team.get(team_id)
            if team.get_domain_membership(domain) and team.get_domain_membership(domain).role:
                dm_list.append([team.get_domain_membership(domain), '(' + team_name + ')'])

        #now find out which dm has the highest permissions
        if dm_list:
            role = self.total_domain_membership(dm_list, domain)
            dm = CustomDomainMembership(subject=domain, custom_role=role)
            return dm.has_permission(permission, data)
        else:
            return False



    def get_role(self, item=None):
        """
        Get the role object for this user

        """
        domain = item
        from corehq.apps.orgs.models import Team
        if domain is None:
            # default to current_domain for django templates
            domain = self.current_domain

        if self.is_global_admin():
            return AdminDomainUserRole(subject=domain)

        dm_list = list()

        dm = self.get_domain_membership(domain)
        if dm:
            dm_list.append([dm, ''])

        for team_name, team_id in self.teams:
            team = Team.get(team_id)
            if team.get_domain_membership(domain) and team.get_domain_membership(domain).role:
                dm_list.append([team.get_domain_membership(domain), ' (' + team_name + ')'])

        #now find out which dm has the highest permissions
        if dm_list:
            return self.total_domain_membership(dm_list, domain)
        else:
            raise DomainMembershipError()



    def total_domain_membership(self, domain_memberships, domain):
        #sort out the permissions
        total_permission = DomainPermissions()
        total_reports_list = list()
        if domain_memberships:
            for domain_membership, membership_source in domain_memberships:
                permission = domain_membership.permissions
                total_permission |= permission

            #set up a user role
        return DomainUserRole(domain=domain, permissions=total_permission, name=', '.join([(domain_membership.role.name or 'None') + membership_source for domain_membership, membership_source in domain_memberships]))

class FakeUser(WebUser):
    """
    Prevent actually saving user types that don't exist in the database
    """
    def save(self, **kwargs):
        raise NotImplementedError("You aren't allowed to do that!")
        
    
class PublicUser(FakeUser):
    """
    Public users have read-only access to certain domains
    """

    domain_memberships = None

    def __init__(self, domain, **kwargs):
        super(PublicUser, self).__init__(**kwargs)
        self.domain = domain
        self.domains = [domain]
        dm = CustomDomainMembership(subject=domain, is_admin=False)
        dm.set_permission('view_reports', True)
        self.domain_memberships = [dm]

    def get_role(self, domain=None):
        assert(domain == self.domain)
        return super(PublicUser, self).get_role(domain)

class InvalidUser(FakeUser):
    """
    Public users have read-only access to certain domains
    """
    
    def is_member_of(self, domain_qs):
        return False
    
#
# Django  models go here
#
class Invitation(Document):
    """
    When we invite someone to a domain it gets stored here.
    """
    domain = StringProperty()
    email = StringProperty()
#    is_domain_admin = BooleanProperty()
    invited_by = StringProperty()
    invited_on = DateTimeProperty()
    is_accepted = BooleanProperty(default=False)

    role = StringProperty()

    _inviter = None
    def get_inviter(self):
        if self._inviter is None:
            self._inviter = CouchUser.get_by_user_id(self.invited_by)
            if self._inviter.user_id != self.invited_by:
                self.invited_by = self._inviter.user_id
                self.save()
        return self._inviter

    def send_activation_email(self):

        url = "http://%s%s" % (Site.objects.get_current().domain,
                               reverse("accept_invitation", args=[self.domain, self.get_id]))
        params = {"domain": self.domain, "url": url, "inviter": self.get_inviter().formatted_name}
        text_content = render_to_string("domain/email/domain_invite.txt", params)
        html_content = render_to_string("domain/email/domain_invite.html", params)
        subject = 'Invitation from %s to join CommCareHQ' % self.get_inviter().formatted_name
        send_HTML_email(subject, self.email, text_content, html_content)

class RemoveWebUserRecord(DeleteRecord):
    user_id = StringProperty()
    domain_membership = SchemaProperty(DomainMembership)

    def undo(self):
        user = WebUser.get_by_user_id(self.user_id)
        user.add_domain_membership(**self.domain_membership._doc)
        user.save()

from .signals import *
from corehq.apps.domain.models import Domain
