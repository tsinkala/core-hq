import functools
from django.http import HttpResponseRedirect
from corehq.apps.users.models import WebUser
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
            return HttpResponseRedirect(reverse("domain_select"))
    return inner


