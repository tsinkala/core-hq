from couchdbkit.ext.django.schema import Document, StringProperty, DateTimeProperty, BooleanProperty
from django.contrib import messages
from django.contrib.auth.views import redirect_to_login
from django.contrib.sites.models import Site
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from django.template.loader import render_to_string
from corehq.apps.hqwebapp.views import logout
from corehq.apps.registration.forms import NewWebUserRegistrationForm
from corehq.apps.registration.utils import activate_new_user
from corehq.apps.users.models import CouchUser
from dimagi.utils.django.email import send_HTML_email
from dimagi.utils.web import render_to_response

class Invitation(Document):
    email = StringProperty()
    invited_by = StringProperty()
    invited_on = DateTimeProperty()
    is_accepted = BooleanProperty(default=False)

    _inviter = None
    def get_inviter(self):
        if self._inviter is None:
            self._inviter = CouchUser.get_by_user_id(self.invited_by)
            if self._inviter.user_id != self.invited_by:
                self.invited_by = self._inviter.user_id
                self.save()
        return self._inviter

    def send_activation_email(self):
        raise NotImplementedError


class DomainInvitation(Invitation):
    """
    When we invite someone to a domain it gets stored here.
    """
    domain = StringProperty()
    role = StringProperty()
    doc_type = "Invitation"

    def send_activation_email(self):
        url = "http://%s%s" % (Site.objects.get_current().domain,
                               reverse("domain_accept_invitation", args=[self.domain, self.get_id]))
        params = {"domain": self.domain, "url": url, "inviter": self.get_inviter().formatted_name}
        text_content = render_to_string("domain/email/domain_invite.txt", params)
        html_content = render_to_string("domain/email/domain_invite.html", params)
        subject = 'Invitation from %s to join CommCareHQ' % self.get_inviter().formatted_name
        send_HTML_email(subject, self.email, html_content, text_content=text_content)

    @classmethod
    def by_domain(cls, domain, is_active=True):
        key = [domain]

        return cls.view("users/open_invitations_by_domain",
            reduce=False,
            startkey=key,
            endkey=key + [{}],
            include_docs=True,
        ).all()


class OrgInvitation(Invitation):
    doc_type = "OrgInvitation"
    organization = StringProperty()

    def send_activation_email(self):
        url = "http://%s%s" % (Site.objects.get_current().domain,
                               reverse("orgs_accept_invitation", args=[self.organization, self.get_id]))
        params = {"organization": self.organization, "url": url, "inviter": self.get_inviter().formatted_name}
        text_content = render_to_string("orgs/email/org_invite.txt", params)
        html_content = render_to_string("orgs/email/org_invite.html", params)
        subject = 'Invitation from %s to join CommCareHQ' % self.get_inviter().formatted_name
        send_HTML_email(subject, self.email, html_content, text_content=text_content)


class InvitationView():
    inv_type = Invitation
    template = ""
    need = [] # a list of strings containing which parameters of the call function should be set as attributes to self

    def added_context(self):
        return {}

    def validate_invitation(self, invitation):
        pass

    @property
    def success_msg(self):
        return "You have been successfully invited"

    @property
    def redirect_to_on_success(self):
        raise NotImplementedError

    def invite(self, invitation, user):
        raise NotImplementedError

    def _invite(self, invitation, user):
        self.invite(invitation, user)
        invitation.is_accepted = True
        invitation.save()
        messages.success(self.request, self.success_msg)

    def __call__(self, request, invitation_id, **kwargs):
        # add the correct parameters to this instance
        self.request = request
        for k, v in kwargs.iteritems():
            if k in self.need:
                setattr(self, k, v)

        if request.GET.get('switch') == 'true':
            logout(request)
            return redirect_to_login(request.path)
        if request.GET.get('create') == 'true':
            logout(request)
            return HttpResponseRedirect(request.path)

        invitation = self.inv_type.get(invitation_id)

        if invitation.is_accepted:
            messages.error(request, "Sorry, that invitation has already been used up. "
                                    "If you feel this is a mistake please ask the inviter for "
                                    "another invitation.")
            return HttpResponseRedirect(reverse("login"))

        self.validate_invitation(invitation)

        if request.user.is_authenticated():
            if request.couch_user.username != invitation.email:
                messages.error(request, "The invited user %s and your user %s do not match!" % (invitation.email, request.couch_user.username))

            if request.method == "POST":
                couch_user = CouchUser.from_django_user(request.user)
                self._invite(invitation, couch_user)
                return HttpResponseRedirect(self.redirect_to_on_success)
            else:
                mobile_user = CouchUser.from_django_user(request.user).is_commcare_user()
                context = self.added_context()
                context.update({
                    'mobile_user': mobile_user,
                    "invited_user": invitation.email if request.couch_user.username != invitation.email else "",
                    })
                return render_to_response(request, self.template, context)
        else:
            if request.method == "POST":
                form = NewWebUserRegistrationForm(request.POST)
                if form.is_valid():
                    # create the new user
                    user = activate_new_user(form)
                    user.save()
                    messages.success(request, "User account for %s created! You may now login." % form.cleaned_data["email"])
                    self._invite(invitation, user)
                    return HttpResponseRedirect(reverse("login"))
            else:
                form = NewWebUserRegistrationForm(initial={'email': invitation.email})

        return render_to_response(request, self.template, {"form": form})
