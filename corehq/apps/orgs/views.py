from django.core.urlresolvers import reverse
from django.http import HttpResponse, HttpResponseRedirect, Http404, HttpResponseForbidden
from django.views.decorators.http import require_POST
from corehq.apps.domain.decorators import require_superuser
from corehq.apps.orgs.decorators import require_org_member
from corehq.apps.registration.forms import DomainRegistrationForm
from corehq.apps.orgs.forms import AddProjectForm, AddMemberForm, AddTeamForm, UpdateOrgInfo
from corehq.apps.users.models import CouchUser, WebUser, AdminDomainUserRole, DomainUserRole, AdminOrganizationUserRole, OrganizationUserRole
from corehq.apps.users.views import require_can_edit_commcare_users
from dimagi.utils.web import render_to_response, json_response, get_url_base
from corehq.apps.orgs.models import Organization, Team, DeleteTeamRecord
from corehq.apps.domain.models import Domain
from django.contrib import messages
from dimagi.utils.couch.resource_conflict import repeat



def orgs_base(request, template="orgs/orgs_base.html"):
    organizations = Organization.get_all()
    vals = dict(orgs = organizations)
    return render_to_response(request, template, vals)

@require_org_member
def orgs_landing(request, org, template="orgs/orgs_landing.html", form=None, add_form=None, add_member_form=None, add_team_form=None, update_form=None):
    organization = Organization.get_by_name(org)

    reg_form_empty = not form
    add_form_empty = not add_form
    add_member_form_empty = not add_member_form
    add_team_form_empty = not add_team_form
    update_form_empty = not update_form

    reg_form = form or DomainRegistrationForm(initial={'org': organization.name})
    add_form = add_form or AddProjectForm(org)

    role_choices = OrganizationUserRole.role_choices(org)
    add_member_form = add_member_form or AddMemberForm(org, role_choices=role_choices)
    add_team_form = add_team_form or AddTeamForm(org)

    update_form = update_form or UpdateOrgInfo(initial={'org_title': organization.title, 'email': organization.email, 'url': organization.url, 'location': organization.location})
    current_teams = Team.get_by_org(org)

    members = [WebUser.get_by_user_id(user_id) for user_id in organization.members]
    username = request.user.username
    user = WebUser.get_by_username(username)
    membership = user.organization_manager.get_membership(user, item=org)
    if membership:
        permission = membership.permissions
    else:
        permission = OrganizationUserRole.get_default()

    org_domains = Domain.get_by_organization(org)
    if user.is_global_admin() or user.organization_manager.is_admin(user):
        current_domains = org_domains
    else:
        user_domain_names = user.get_domains()
        user_domains = list()
        for name in user_domain_names:
            user_domains.append(Domain.get_by_name(name))
        current_domains = list()
        for od in org_domains:
            for ud in user_domains:
                if (od and ud) and od.get_id == ud.get_id:
                    current_domains.append(od)

    vals = dict( org=organization, domains=current_domains, reg_form=reg_form,
                 add_form=add_form, reg_form_empty=reg_form_empty, add_form_empty=add_form_empty, update_form=update_form, update_form_empty=update_form_empty, add_member_form=add_member_form, add_member_form_empty=add_member_form_empty, add_team_form=add_team_form, add_team_form_empty=add_team_form_empty, teams=current_teams, members=members, permission=permission, membership=membership)
    return render_to_response(request, template, vals)

@require_org_member
def orgs_members(request, org, template='orgs/orgs_members.html'):
    organization = Organization.get_by_name(org)
    couch_user = request.couch_user
    members = [WebUser.get_by_user_id(user_id) for user_id in organization.members]
    roles = list()
    for member in members:
        roles.append([member, member.organization_manager.role_label(member, org)])
    user_roles = [AdminOrganizationUserRole(subject=org)]
    user_roles.extend(sorted(OrganizationUserRole.by_subject(org), key=lambda role: role.name if role.name else u'\uFFFF'))
    current_teams = Team.get_by_org(org)
    current_domains = Domain.get_by_organization(org)
    username = request.user.username
    user = WebUser.get_by_username(username)
    membership = user.organization_manager.get_membership(user, item=org)
    if membership:
        permission = membership.permissions
    else:
        permission = OrganizationUserRole.get_default()
    vals = dict(org=organization, members=roles, couch_user=couch_user, user_roles=user_roles, default_role=OrganizationUserRole.get_default(), teams=current_teams, domains=current_domains, membership=membership, permission=permission)
    return render_to_response(request, template, vals)

@require_org_member
def get_data(request, org):
    organization = Organization.get_by_name(org)
    return json_response(organization)

@require_org_member
def orgs_new_project(request, org):
    from corehq.apps.registration.views import register_domain
    if request.method == 'POST':
        return register_domain(request)
    else:
        return orgs_landing(request, org, form=DomainRegistrationForm())

@require_org_member
def orgs_update_info(request, org):
    organization = Organization.get_by_name(org)
    if request.method == "POST":
        form = UpdateOrgInfo(request.POST, request.FILES)
        if form.is_valid():
            logo = None
            if form.cleaned_data['org_title'] or organization.title:
                organization.title = form.cleaned_data['org_title']
            if form.cleaned_data['email'] or organization.email:
                organization.email = form.cleaned_data['email']
            if form.cleaned_data['url'] or organization.url:
                organization.url = form.cleaned_data['url']
            if form.cleaned_data['location'] or organization.location:
                organization.location = form.cleaned_data['location']
                #logo not working, need to look into this
            if form.cleaned_data['logo']:
                logo = form.cleaned_data['logo']
                if organization.logo_filename:
                    organization.delete_attachment(organization.logo_filename)
                organization.logo_filename = logo.name

            organization.save()
            if logo:
                organization.put_attachment(content=logo.read(), name=logo.name)
        else:
            return orgs_landing(request, org, update_form=form)
    return HttpResponseRedirect(reverse('orgs_landing', args=[org]))


@require_org_member
def orgs_add_project(request, org):
    if request.method == "POST":
        form = AddProjectForm(org, request.POST)
        if form.is_valid():
            domain_name = form.cleaned_data['domain_name']
            dom = Domain.get_by_name(domain_name)
            dom.organization = org
            dom.slug = form.cleaned_data['domain_slug']
            dom.save()
            messages.success(request, "Project Added!")
        else:
            messages.error(request, "Unable to add project")
            return orgs_landing(request, org, add_form=form)
    return HttpResponseRedirect(reverse('orgs_landing', args=[org]))

@require_org_member
def orgs_add_member(request, org, team_id=None):
    if request.method == "POST":
        role_choices = OrganizationUserRole.role_choices(org)
        form = AddMemberForm(org, request.POST, role_choices=role_choices)
        if form.is_valid():
            username = form.cleaned_data['member_email']
            role_id = form.cleaned_data['role']
            user = CouchUser.get_by_username(username)
            user.organization_manager.add_membership(user, item=org)
            user.organization_manager.set_role(user, org, role_id)
            user.save()
            user_id = user.userID
            organization = Organization.get_by_name(org)
            organization.add_member(user_id)
            messages.success(request, "Member Added!")
        else:
            messages.error(request, "Unable to add member")
            if 'redirect_url' in request.POST:
                return orgs_team_members(request, org, team_id)
            return orgs_landing(request, org, add_member_form=form)
    if 'redirect_url' in request.POST:
        return join_team(request, org, team_id, user_id)
    return HttpResponseRedirect(reverse('orgs_landing', args=[org]))

@require_org_member
def orgs_remove_member(request, org, member_id):
    organization = Organization.get_by_name(org)
    member = WebUser.get(member_id)
    #remove in members
    organization.members.remove(member_id)
    #remove the membership
    member.organization_manager.delete_membership(member, org)
    member.save()


    org_teams = Team.get_by_org(org)
    for team_name, team_id in member.teams:
        team = Team.get(team_id)
        for org_team in org_teams:
            if team.get_id in org_team.get_id:
                team.remove_member(member_id)


    organization.save()
    return HttpResponseRedirect(reverse('orgs_members', args=[org]))

@require_org_member
def orgs_add_team(request, org):
    if request.method == "POST":
        form = AddTeamForm(org, request.POST)
        if form.is_valid():
            team_name = form.cleaned_data['team']
            team = Team(name=team_name, organization=org)
            team.save()
            messages.success(request, "Team Added!")
        else:
            messages.error(request, "Unable to add team")
            return orgs_landing(request, org, add_team_form=form)
    return HttpResponseRedirect(reverse('orgs_landing', args=[org]))

@require_org_member
def orgs_logo(request, org):
    organization = Organization.get_by_name(org)
    if organization.logo_filename:
        image = organization.get_logo()
    else:
        image = None
    return HttpResponse(image, content_type='image/gif')

@require_org_member
def orgs_teams(request, org, template="orgs/orgs_teams.html"):
    organization = Organization.get_by_name(org)
    teams = Team.get_by_org(org)
    current_domains = Domain.get_by_organization(org)
    vals = dict(org=organization, teams=teams, domains=current_domains)
    return render_to_response(request, template, vals)

@require_org_member
def orgs_team_members(request, org, team_id, add_member_form=None, template="orgs/orgs_team_members.html"):
    #organization and teams
    organization = Organization.get_by_name(org)
    teams = Team.get_by_org(org)
    current_domains = Domain.get_by_organization(org)

    add_member_form_empty = not add_member_form
    role_choices = OrganizationUserRole.role_choices(org)
    add_member_form = add_member_form or AddMemberForm(org, role_choices=role_choices)

#check that the team exists
    team = Team.get(team_id)
    if team is None:
        raise Http404("Group %s does not exist" % team_id)

    #inspect the members of the team

    member_ids = team.get_member_ids()
    members = WebUser.view("_all_docs", keys=member_ids, include_docs=True).all()
    members.sort(key=lambda user: user.username)

    #inspect the domains of the team
    domain_names = team.get_domains()
    domains = list()
    for name in domain_names:
        user_roles = [AdminDomainUserRole(subject=name)]
        user_roles.extend(sorted(DomainUserRole.by_subject(name), key=lambda role: role.name if role.name else u'\uFFFF'))
        roles = []
        for user_role in user_roles:
            roles.append([user_role, user_role.get_qualified_id().replace(':', '_')])
        domains.append([Domain.get_by_name(name), team.role_label(item=name), roles])


    all_org_domains = Domain.get_by_organization(org)
    non_domains = [domain for domain in all_org_domains if domain.name not in domain_names]

    all_org_member_ids = organization.members
    all_org_members = WebUser.view("_all_docs", keys=all_org_member_ids, include_docs=True).all()
    non_members = [member for member in all_org_members if member.user_id not in member_ids]


    username = request.user.username
    user = WebUser.get_by_username(username)
    membership = user.organization_manager.get_membership(user, item=org)
    if membership:
        permission = membership.permissions
    else:
        permission = OrganizationUserRole.get_default()

    vals = dict(org=organization, team=team, teams=teams, members=members, nonmembers=non_members, domains=current_domains, team_domains=domains, team_nondomains=non_domains, permission=permission, membership=membership, add_member_form=add_member_form, add_member_form_empty=add_member_form_empty)
    return render_to_response(request, template, vals)

@require_org_member
def add_team(request, org):
    team_name = request.POST['team_name']
    team = Team.get_by_org_and_name(org, team_name)
    if not team:
        team = Team(name=team_name, organization=org)
        team.is_global_admin()
        team.save()
    return HttpResponseRedirect(reverse("orgs_team_members", args=(org, team.get_id)))


@require_org_member
def join_team(request, org, team_id, couch_user_id):
    def add_user():
        team = Team.get(team_id)
        if team:
            team.add_member(couch_user_id)
    repeat(add_user, 3)
    if 'redirect_url' in request.POST:
        return HttpResponseRedirect(reverse(request.POST['redirect_url'], args=(org, team_id)))

@require_org_member
def leave_team(request, org, team_id, couch_user_id):
    def remove_user():
        team = Team.get(team_id)
        if team:
            team.remove_member(couch_user_id)
    repeat(remove_user, 3)
    if 'redirect_url' in request.POST:
        return HttpResponseRedirect(reverse(request.POST['redirect_url'], args=(org, team_id)))

@require_POST
@require_org_member
def delete_team(request, org, team_id):
    team = Team.get(team_id)
    if team.organization == org:
        record = team.soft_delete()
        for member_id in team.member_ids:
            team_member = WebUser.get(member_id)
            for team_name, team_id in team_member.teams:
                if team_id == team.get_id:
                    team_member.teams.remove([team_name, team_id])
            team_member.save()
        messages.success(request, 'You have deleted a team. <a href="{url}" class="post-link">Undo</a>'.format(
            url=reverse('undo_delete_team', args=[org, record.get_id])
        ), extra_tags="html")
        return HttpResponseRedirect(reverse("orgs_teams", args=(org, )))
    else:
        return HttpResponseForbidden()

@require_org_member
def undo_delete_team(request, org, record_id):
    record = DeleteTeamRecord.get(record_id)
    record.undo()
    team = Team.get(record.doc_id)
    for member_id in team.get_member_ids():
        team_member = WebUser.get(member_id)
        team_member.teams.append([team.name, team.get_id])
        team_member.save()
    return HttpResponseRedirect(reverse('orgs_team_members', args=[org, record.doc_id,]))

@require_org_member
def add_domain_to_team(request, org, team_id, domain):
    team = Team.get(team_id)
    if team:
        team.add_domain_membership(domain)
        team.save()
    if 'redirect_url' in request.POST:
        return HttpResponseRedirect(reverse(request.POST['redirect_url'], args=(org, team_id)))

@require_org_member
def remove_domain_from_team(request, org, team_id, domain):
    team = Team.get(team_id)
    if team:
        team.delete_domain_membership(domain)
        team.save()
    if 'redirect_url' in request.POST:
        return HttpResponseRedirect(reverse(request.POST['redirect_url'], args=(org, team_id)))

@require_org_member
def set_team_permission_for_domain(request, org, team_id, domain, role_label):
    team = Team.get(team_id)
    if team:
        role_label = role_label.replace('_', ':')
        team.set_role(domain, role_label)
        team.save()
    return HttpResponseRedirect(reverse('orgs_team_members', args=(org, team_id)))

@require_org_member
def add_all_to_team(request, org, team_id):
    team = Team.get(team_id)
    if team:
        organization = Organization.get_by_name(org)
        members = organization.members
        for member in members:
            team.add_member(member)
    if 'redirect_url' in request.POST:
        return HttpResponseRedirect(reverse(request.POST['redirect_url'], args=(org, team_id)))

@require_org_member
def remove_all_from_team(request, org, team_id):
    team = Team.get(team_id)
    if team:
        member_ids = team.member_ids
        for member in member_ids:
            team.remove_member(member)
    if 'redirect_url' in request.POST:
        return HttpResponseRedirect(reverse(request.POST['redirect_url'], args=(org, team_id)))
