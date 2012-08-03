import functools
from django.http import HttpResponseRedirect
from corehq.apps.users.models import WebUser, OrganizationUserRole
from lib.django_rest_interface.resource import reverse

def require_org_member(view):
    """
    decorator to prevent nonmembers of organizations from accessing an organization's page
    """
    @functools.wraps(view)
    def inner(request, org, *args, **kwargs):
        username = request.user.username
        user = WebUser.get_by_username(username)
        if user.organization_manager.is_member_of(user, org):
            return view(request, org, *args, **kwargs)
        else:
            return HttpResponseRedirect(reverse("orgs_base"))
    return inner

def require_org_admin(view):
    """
    decorator to prevent nonmembers of organizations from accessing an organization's page
    """
    @functools.wraps(view)
    def inner(request, org, *args, **kwargs):
        username = request.user.username
        user = WebUser.get_by_username(username)
        membership, permission = get_membership_and_permission(user, org)
        if membership.is_admin:
            return view(request, org, *args, **kwargs)
        else:
            return HttpResponseRedirect(reverse('orgs_landing', args=(org,)))
    return inner



def require_org_team_manager(view):
    """
    decorator to prevent nonmembers of organizations from accessing an organization's page
    """
    @functools.wraps(view)
    def inner(request, org, *args, **kwargs):
        username = request.user.username
        user = WebUser.get_by_username(username)
        membership, permission = get_membership_and_permission(user, org)
        if permission.edit_teams:
            return view(request, org, *args, **kwargs)
        else:
            return HttpResponseRedirect(reverse('orgs_landing', args=(org,)))
    return inner

def require_org_project_manager(view):
    """
    decorator to prevent nonmembers of organizations from accessing an organization's page
    """
    @functools.wraps(view)
    def inner(request, org, *args, **kwargs):
        username = request.user.username
        user = WebUser.get_by_username(username)
        membership, permission = get_membership_and_permission(user, org)
        if permission.edit_projects:
            return view(request, org, *args, **kwargs)
        else:
            return HttpResponseRedirect(reverse('orgs_landing', args=(org,)))
    return inner


def get_membership_and_permission(user, org):
    membership = user.organization_manager.get_membership(user, item=org)
    if membership:
        permission = membership.permissions
    else:
        permission = OrganizationUserRole.get_default()
    return membership, permission