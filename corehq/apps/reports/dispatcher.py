from django.core.urlresolvers import reverse
from django.http import Http404, HttpResponseRedirect
from django.template.loader import render_to_string
from django.utils.safestring import mark_safe
from django.views.generic.base import View
from corehq.apps.domain.decorators import login_and_domain_required, cls_to_view
from dimagi.utils.decorators.datespan import datespan_in_request
from django.utils.translation import ugettext as _

from corehq.apps.domain.models import Domain

datespan_default = datespan_in_request(
    from_param="startdate",
    to_param="enddate",
    default_days=7,
)

class ReportDispatcher(View):
    """
        The ReportDispatcher is responsible for dispatching the correct reports or interfaces
        based on a REPORT_MAP or INTERFACE_MAP specified in settings.

        The mapping should be structured as follows.

        REPORT_MAP = {
            "Section Name" : [
                'app.path.to.report.ReportClass',
            ]
        }

        It is intended that you subclass this dispatcher and specify the map_name settings attribute
        and a unique prefix (like project in project_report_dispatcher).

        It's also intended that you make the appropriate permissions checks in the permissions_check method
        and decorate the dispatch method with the appropriate permissions decorators.

        ReportDispatcher expects to serve a report that is a subclass of GenericReportView.
    """
    prefix = None # string. ex: project, custom, billing, interface, admin
    map_name = None

    def __init__(self, **kwargs):
        if not self.map_name or not isinstance(self.map_name, basestring): # unicode?
            raise NotImplementedError("Class property 'map_name' must be a string, and not empty.")
        super(ReportDispatcher, self).__init__(**kwargs)

    @property
    def slug_aliases(self):
        """
            For those times when you merge a report or delete it and still want to keep around the old link.
            Format like:
            { 'old_slug': 'new_slug' }
        """
        return {}

    @classmethod
    def permissions_check(cls, report, domain=None, couch_user=None):
        """
            Override this method to check for appropriate permissions based on the report model
            and other arguments.
        """
        return True

    @classmethod
    def get_reports(cls, check_permissions=True, domain=None, couch_user=None,
                    project=None):
        """
        Single point of truth for getting the list of visible reports for a
        domain given a couch_user and domain object.  Returns a list of
        (section name, list of report classes) tuples.
        
        Pass check_permissions=False to disable permissions checking, which
        prevents you from needing to pass values for couch_user and project.

        """
        attr_name = cls.map_name
        import corehq
        domain_module = Domain.get_module_by_name(domain)

        all_reports = (
            getattr(corehq, attr_name, ()) +
            getattr(domain_module, attr_name, ())
        )

        ret = []

        for section_name, reports in all_reports:
            current_section = []
            for report in reports:
                if (not check_permissions or
                    report.is_visible(domain=domain,
                            couch_user=couch_user, project=project)):
                    current_section.append(report)
            if current_section:
                ret.append((section_name, current_section))

        return ret

    @classmethod
    def get_reports_dict(cls, domain=None, **kwargs):
        """
        Returns a dictionary of report classes keyed by report slug.  Takes the
        same keyword arguments as get_reports().
        
        """
        return dict((report.slug, report)
                    for name, group in cls.get_reports(domain, **kwargs)
                    for report in group)

    @classmethod
    def get_report(cls, report_slug, domain=None, **kwargs):
        """
        Returns the report class for `report_slug`, or None if no report is
        found.

        """
        return cls.get_reports_dict(domain, **kwargs).get(report_slug, None)

    def _redirect_slug(self, slug):
        return self.slug_aliases.get(slug) is not None

    def _slug_alias(self, slug):
        return self.slug_aliases.get(slug)

    def dispatch(self, request, domain=None, report_slug=None, render_as=None,
                 *args, **kwargs):
        render_as = render_as or 'view'
        domain = domain or getattr(request, 'domain', None)
        couch_user = getattr(request, 'couch_user', None)
        project = getattr(request, 'project', None)

        redirect_slug = self._redirect_slug(report_slug)

        if redirect_slug and render_as == 'email':
            # todo saved reports should probably change the slug to the redirected slug. this seems like a hack.
            raise Http404
        elif redirect_slug:
            new_args = [domain] if domain else []
            if render_as != 'view':
                new_args.append(render_as)
            new_args.append(redirect_slug)
            return HttpResponseRedirect(reverse(self.name(), args=new_args))

        cls = self.get_report(report_slug, domain=domain,
                couch_user=couch_user, project=project)

        if not cls:
            raise Http404()

        report = cls(request, domain=domain, **kwargs)
        report.rendered_as = render_as
        return getattr(report, '%s_response' % render_as)

    @classmethod
    def name(cls):
        prefix = "%s" % cls.prefix if cls.prefix else ""
        return "%s_dispatcher" % prefix

    @classmethod
    def _rendering_pattern(cls):
        return "(?P<render_as>[{renderings}]+)".format(
            renderings="|".join("(%s)" % r for r in cls.allowed_renderings())
        )

    @classmethod
    def pattern(cls):
        return r'^({renderings}/)?(?P<report_slug>[\w_]+)/$'.format(renderings=cls._rendering_pattern())

    @classmethod
    def allowed_renderings(cls):
        return ['json', 'async', 'filters', 'export', 'mobile', 'email', 'partial']

    @classmethod
    def navigation_sections(cls, domain=None, couch_user=None, project=None):
        nav_context = []

        accessible_reports = cls.get_reports(domain=domain,
                couch_user=couch_user, project=project)

        for section_name, report_group in accessible_reports:
            report_contexts = []
            for report in report_group:
                class_name = report.__module__ + '.' + report.__name__
                if not cls.permissions_check(class_name, domain=domain,
                        couch_user=couch_user):
                    continue
                if report.is_visible(domain=domain,
                        couch_user=couch_user, project=project):
                    if hasattr(report, 'override_navigation_list'):
                        report_contexts.extend(
                                report.override_navigation_list(domain=domain))
                    else:
                        report_contexts.append({
                            'url': report.get_url(domain=domain),
                            'description': report.description,
                            'icon': report.icon,
                            'title': report.name,
                        })
            if report_contexts:
                nav_context.append((section_name, report_contexts))
        return nav_context

    @classmethod
    def url_pattern(cls):
        from django.conf.urls.defaults import url
        return url(cls.pattern(), cls.as_view(), name=cls.name())

cls_to_view_login_and_domain = cls_to_view(additional_decorator=login_and_domain_required)

class ProjectReportDispatcher(ReportDispatcher):
    prefix = 'project_report' # string. ex: project, custom, billing, interface, admin
    map_name = 'REPORTS'

    @property
    def slug_aliases(self):
        return {
            'daily_completions': 'daily_form_stats',
            'daily_submissions': 'daily_form_stats',
            'submit_time_punchcard': 'worker_activity_times',
        }

    @cls_to_view_login_and_domain
    @datespan_default
    def dispatch(self, request, *args, **kwargs):
        return super(ProjectReportDispatcher, self).dispatch(request, *args, **kwargs)

    @classmethod
    def permissions_check(self, report, domain=None, couch_user=None):
        if domain is None:
            return False
        return couch_user.can_view_report(domain, report)

class CustomProjectReportDispatcher(ProjectReportDispatcher):
    prefix = 'custom_project_report'
    map_name = 'CUSTOM_REPORTS'
