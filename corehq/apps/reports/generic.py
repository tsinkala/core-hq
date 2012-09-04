from StringIO import StringIO
import datetime
from celery.log import get_task_logger
from django.core.urlresolvers import reverse
from django.http import HttpResponse
from django.template.context import RequestContext
import json
from django.template.loader import render_to_string
import pickle
import pytz
from corehq.apps.reports import util
from corehq.apps.reports.datatables import DataTablesHeader
from corehq.apps.users.models import CouchUser
from couchexport.export import export_from_tables
from couchexport.shortcuts import export_response
from dimagi.utils.couch.pagination import DatatablesParams
from dimagi.utils.dates import DateSpan
from dimagi.utils.modules import to_function
from dimagi.utils.web import render_to_response, json_request

class GenericReportView(object):
    """
        A generic report structure for viewing a report
        (or pages that follow the reporting structure closely---though that seems a bit hacky)

        This object is handled by the ReportDispatcher and served as a django view based on
        the report maps specified in settings.py

        To make the report return anything, override any or all of the following properties:

        @property
        template_context
            - returns a dict to be inserted into self.context
            - only items relevant to base_template structure should be placed here. Anything
                related to report data and async templates should be done in report_context

        @property
        report_context
            - returns a dict to be inserted into self.context
            - this is where the main processing of the report data should happen
            - can be cached using @cache_report decorator in memcached where you please

        Note: In general you should not be inserting things into self.context directly, unless absolutely
            necessary. Please use the structure in the above properties for updating self.context
            in the relevant places.

        @property
        json_dict
            - returns a dict to be parsed and returned as json for the json version of this report
                (generally has only been useful for datatables paginated reports)

        @property
        export_table
            - returns a multi-dimensional list formatted as export_from_tables would expect:
                [ ['table_or_sheet_name', [['header'] ,['row']] ] ]


    """
    # required to create a report based on this
    name = None         # string. the name of the report that shows up in the heading and the
    slug = None         # string. the report_slug_in_the_url
    section_name = None # string. ex: "Reports"
    app_slug = None     # string. ex: 'reports' or 'manage'
    dispatcher = None   # ReportDispatcher subclass
    # todo: find instances of base_slug and replace with section_slug

    # not required
    description = None  # string. description of the report. Currently not being used.
    report_template_path = None
    report_partial_path = None

    asynchronous = False
    hide_filters = False
    fields = None

    exportable = False
    export_format_override = None
    icon = None

    # the defaults for this should be sufficient. But if they aren't, well go for it.
    base_templates = dict(
        base=None,
        base_async=None,
        filters=None
    )

    flush_layout = False
    # Todo: maybe make these a little cleaner?
    show_timezone_notice = False
    show_time_notice = False
    is_admin_report = False

    def __init__(self, request, base_context=None, *args, **kwargs):
        if not self.name or not self.section_name or self.slug is None or not self.dispatcher:
            raise NotImplementedError("Missing a required parameter: (name: %(name)s, section_name: %(section_name)s,"
            " slug: %(slug)s, dispatcher: %(dispatcher)s" % dict(
                name=self.name,
                section_name=self.section_name,
                slug=self.slug,
                dispatcher=self.dispatcher
            ))

        from corehq.apps.reports.dispatcher import ReportDispatcher
        if isinstance(self.dispatcher, ReportDispatcher):
            raise ValueError("Class property dispatcher should point to a subclass of ReportDispatcher.")

        self.request = request
        self.request_params = json_request(self.request.GET)
        self.domain = kwargs.get('domain')
        self.context = base_context or {}
        self._update_initial_context()

    def __str__(self):
        return "%(klass)s report named '%(name)s' with slug '%(slug)s' in section '%(section)s'.%(desc)s%(fields)s" % dict(
            klass=self.__class__.__name__,
            name=self.name,
            slug=self.slug,
            section=self.section_name,
            desc="\n   Report Description: %s" % self.description if self.description else "",
            fields="\n   Report Fields: \n     -%s" % "\n     -".join(self.fields) if self.fields else ""
        )

    def __getstate__(self):
        """
            For pickling the report when passing it to Celery.
        """
        logging = get_task_logger() # logging lis likely to happen within celery.
        # pickle only what the report needs from the request object

        request = dict(
            GET=self.request.GET,
            META=dict(
                QUERY_STRING=self.request.META.get('QUERY_STRING'),
                PATH_INFO=self.request.META.get('PATH_INFO')
            ),
            datespan=self.request.datespan,
            couch_user=None
        )

        try:
            request.update(couch_user=self.request.couch_user.get_id)
        except Exception as e:
            logging.error("Could not pickle the couch_user id from the request object for report %s. Error: %s" %
                          (self.name, e))
        return dict(
            request=request,
            request_params=self.request_params,
            domain=self.domain,
            context={}
        )

    _caching = False
    def __setstate__(self, state):
        """
            For unpickling a pickled report.
        """
        logging = get_task_logger() # logging lis likely to happen within celery.
        self.domain = state.get('domain')
        self.context = state.get('context', {})

        class FakeHttpRequest(object):
            GET = {}
            META = {}
            couch_user = None
            datespan = None

        request_data = state.get('request')
        request = FakeHttpRequest()
        request.GET = request_data.get('GET', {})
        request.META = request_data.get('META', {})
        request.datespan = request_data.get('datespan')

        try:
            couch_user = CouchUser.get(request_data.get('couch_user'))
            request.couch_user = couch_user
        except Exception as e:
            logging.error("Could not unpickle couch_user from request for report %s. Error: %s" %
                            (self.name, e))
        self.request = request
        self._caching = True
        self.request_params = state.get('request_params')
        self._update_initial_context()

    _url_root = None
    @property
    def url_root(self):
        if self._url_root is None:
            path = self.request.META.get('PATH_INFO', "")
            try:
                root = path[0:path.index(self.slug)]
            except ValueError:
                root = None
            self._url_root = root
        return self._url_root

    @property
    def queried_path(self):
        path = self.request.META.get('PATH_INFO')
        query = self.request.META.get('QUERY_STRING')
        return "%s:%s" % (path, query)

    _domain_object = None
    @property
    def domain_object(self):
        if self._domain_object is None and self.domain is not None:
            from corehq.apps.domain.models import Domain
            self._domain_object = Domain.get_by_name(self.domain)
        return self._domain_object

    _timezone = None
    @property
    def timezone(self):
        if self._timezone is None:
            if not self.domain:
                self._timezone = pytz.utc
            else:
                try:
                    self._timezone = util.get_timezone(self.request.couch_user.user_id, self.domain)
                except AttributeError:
                    self._timezone = util.get_timezone(None, self.domain)
        return self._timezone

    _template_base = None
    @property
    def template_base(self):
        if self._template_base is None:
            self._template_base = self.base_templates.get('base') or "%s/base_template.html" % self.app_slug
        return self._template_base

    _template_async_base = None
    @property
    def template_async_base(self):
        if self._template_async_base is None:
            self._template_async_base = (self.base_templates.get('base_async') or "reports/async/default.html") \
                                        if self.asynchronous else self.template_base
        return self._template_async_base

    _template_report = None
    @property
    def template_report(self):
        if self._template_report is None:
            self._template_report = self.report_template_path or "reports/async/basic.html"
        return self._template_report

    _template_report_partial = None
    @property
    def template_report_partial(self):
        """
            Don't override.
        """
        if self._template_report_partial is None:
            override_partial = self.override_report_partial_template
            self._template_report_partial = override_partial if isinstance(override_partial, str) \
                                                else self.report_partial_path
        return self._template_report_partial

    @property
    def override_report_partial_template(self):
        """
            Here exists future flexibility to do things with selecting the
            report_partial based on get parameters.
        """
        return None

    _template_filters = None
    @property
    def template_filters(self):
        if self._template_filters is None:
            self._template_filters = self.base_templates.get('filters') or "reports/async/filters.html"
        return self._template_filters

    _rendered_report_title = None
    @property
    def rendered_report_title(self):
        """
            Don't override.
        """
        if self._rendered_report_title is None:
            rendered_title = self.render_report_title
            self._rendered_report_title = rendered_title if isinstance(rendered_title, str) else self.name
        return self._rendered_report_title

    @property
    def render_report_title(self):
        """
            Override this to do special report titles that include specific info from the report (ex: a username).
            Inserted into the template as the report title upon rending the report asynchronously or when
            self.asynchronous is false
        """
        return None

    _filter_classes = None
    @property
    def filter_classes(self):
        if self._filter_classes is None:
            filters = []
            fields = self.override_fields
            if not fields:
                fields = self.fields
            for field in fields or []:
                klass = to_function(field)
                filters.append(klass(self.request, self.domain, self.timezone))
            self._filter_classes = filters
        return self._filter_classes

    @property
    def override_fields(self):
        """
            Return a list of fields here if you want to override the class property self.fields
            after this report has already been instantiated.
        """
        return None

    _export_format = None
    @property
    def export_format(self):
        if self._export_format is None:
            from couchexport.models import Format
            self._export_format = self.export_format_override or self.request.GET.get('format', Format.XLS)
        return self._export_format

    _export_name = None
    @property
    def export_name(self):
        """
            Override this if you don't want <slug>.xls or <slug>.csv to be the tabular export filename.
        """
        if self._export_name is None:
            self._export_name = self.slug
        return self._export_name

    @property
    def default_report_url(self):
        return "#"

    @property
    def breadcrumbs(self):
        """
            Override this for custom breadcrumbs.
            Use the format:
            dict(
                title="breadcrumb title",
                link="url title links to"
            )
            This breadcrumb does not include the report title, it's only the links in between the section name
            and the report title.
        """
        return None

    @property
    def template_context(self):
        """
            Intention: Override if necessary.
            Update context specific to the wrapping template here.
            Nothing specific to the report should go here, use report_context for that.
            Must return a dict.
        """
        return dict()

    @property
    def report_context(self):
        """
            Intention: Override
            !!! CRUCIAL: This is where ALL the intense processing of the report data happens.

            DO NOT update self.context from here or anything that gets processed in here.
            The dictionary returned by this function can get cached in memcached to optimize a report.
            Must return a dict.
        """
        return dict()

    @property
    def json_dict(self):
        """
            Intention: Override
            Return a json-parsable dict, as needed by your report.
        """
        return {}

    @property
    def export_table(self):
        """
            Intention: Override
            Returns an export table to be parsed by export_from_tables.
        """
        return [ ['table_or_sheet_name', [['header'] ,['row']] ] ]

    def _validate_context_dict(self, property):
        if not isinstance(property, dict):
            raise TypeError("property must return a dict")
        return property

    def _update_initial_context(self):
        """
            Intention: Don't override.
        """
        self.context.update(
            report=dict(
                title=self.name,
                description=self.description,
                section_name=self.section_name,
                slug=self.slug,
                url_root=self.url_root,
                is_async=self.asynchronous,
                is_exportable=self.exportable,
                dispatcher=self.dispatcher,
                show=self.request.couch_user.can_view_reports() or self.request.couch_user.get_viewable_reports(),
                is_admin=self.is_admin_report # todo is this necessary???
            ),
            show_time_notice=self.show_time_notice,
            domain=self.domain,
            layout_flush_content=self.flush_layout
        )

    def update_filter_context(self):
        """
            Intention: This probably does not need to be overridden in general.
            Updates the context with filter information.
        """
        self.context.update(report_filters=[dict(
            field=f.render(),
            slug=f.slug) for f in self.filter_classes])

    def update_template_context(self):
        """
            Intention: This probably does not need to be overridden in general.
            Please override template_context instead.
        """
        url_args = [] if not self.domain else [self.domain]
        self.context['report'].update(
            show_filters=self.fields or not self.hide_filters,
            breadcrumbs=self.breadcrumbs,
            default_url=self.default_report_url,
            url=self.get_url(*url_args)
        )
        if hasattr(self, 'datespan'):
            self.context.update(datespan=self.datespan)
        if self.show_timezone_notice:
            self.context.update(timezone=dict(
                    now=datetime.datetime.now(tz=self.timezone),
                    zone=self.timezone.zone
                ))
        self.context.update(self._validate_context_dict(self.template_context))

    def update_report_context(self):
        """
            Intention: This probably does not need to be overridden in general.
            Please override report_context instead.
        """
        self.context.update(
            report_partial=self.template_report_partial,
            report_base=self.template_async_base
        )
        self.context['report'].update(
            title=self.rendered_report_title    # overriding the default title
        )
        self.context.update(self._validate_context_dict(self.report_context))

    def generate_cache_key(self, func_name):
        print "GENERATING KEY"
        return "%s:%s" % (self.__class__.__name__, func_name)

    @property
    def view_response(self):
        """
            Intention: Not to be overridden in general.
            Renders the general view of the report template.
        """
        self.update_template_context()
        template = self.template_base
        if not self.asynchronous:
            self.update_filter_context()
            self.update_report_context()
            template = self.template_report
        return render_to_response(self.request, template, self.context)

    @property
    def static_response(self):
        """
            This renders _only_ the static html content of the report. It is intended for
            use by the report scheduler.
        """
        self.context.update(original_template=self.template_report)
        self._template_report = "reports/async/static_only.html"
        return self.async_response

    @property
    def async_response(self):
        """
            Intention: Not to be overridden in general.
            Renders the asynchronous view of the report template, returned as json.
        """
        self.update_template_context()
        self.update_report_context()

        rendered_filters = None
        if bool(self.request.GET.get('hq_filters')):
            self.update_filter_context()
            rendered_filters = render_to_string(self.template_filters, self.context,
                context_instance=RequestContext(self.request)
            )
        rendered_report = render_to_string(self.template_report, self.context,
            context_instance=RequestContext(self.request)
        )

        return HttpResponse(json.dumps(dict(
            filters=rendered_filters,
            report=rendered_report,
            title=self.rendered_report_title,
            slug=self.slug,
            url_root=self.url_root
        )))

    @property
    def filters_response(self):
        """
            Intention: Not to be overridden in general.
            Renders just the filters for the report to be fetched asynchronously.
        """
        self.update_filter_context()
        rendered_filters = render_to_string(self.template_filters, self.context,
            context_instance=RequestContext(self.request)
        )
        return HttpResponse(json.dumps(dict(
            filters=rendered_filters,
            slug=self.slug,
            url_root=self.url_root
        )))

    @property
    def json_response(self):
        """
            Intention: Not to be overridden in general.
            Renders the json version for the report, if available.
        """
        return HttpResponse(json.dumps(self.json_dict))

    @property
    def export_response(self):
        """
            Intention: Not to be overridden in general.
            Returns the tabular export of the data, if available.
        """
        temp = StringIO()
        export_from_tables(self.export_table, temp, self.export_format)
        return export_response(temp, self.export_format, self.export_name)

    @property
    def clear_cache_response(self):
        renderings = self.dispatcher.allowed_renderings()
        try:
            del renderings[renderings.index('clear_cache')]
        except Exception:
            pass
        print renderings
        for render in renderings:
            cache_key = self.generate_cache_key("%s_response" % render)
            print cache_key
        return HttpResponse("Clearing cache")

    @classmethod
    def get_url(cls, *args, **kwargs):
        type = kwargs.get('render_as')
        reverse_args = list(args)
        if type:
            if type is not None and type not in cls.dispatcher.allowed_renderings():
                raise ValueError('The type parameter is not one of the following allowed values: %s' %
                                 ', '.join(cls.dispatcher.allowed_renderings()))
            reverse_args.append(type+'/')
        return reverse(cls.dispatcher.name(), args=reverse_args+[cls.slug])

    @classmethod
    def show_in_navigation(cls, request, *args, **kwargs):
        return True


class GenericTabularReport(GenericReportView):
    """
        Override the following properties:
        @property
        headers
            - returns a DataTablesHeader object

        @property
        rows
            - returns a 2D list of rows.

        ## AJAX pagination
        If you plan on using ajax pagination, take into consideration
        the following properties when rendering self.rows:
        self.pagination.start (skip)
        self.pagination.count (limit)

        Make sure you also override the following properties as necessary:
        @property
        total_records
            - returns an integer
            - the total records of what you are paginating over

        @property
        shared_pagination_GET_params
            - this is where you select the GET parameters to pass to the paginator
            - returns a list formatted like [dict(name='group', value=self.group_name)]
    """
    # new class properties
    total_row = None
    default_rows = 10
    start_at_row = 0
    show_all_rows = False
    fix_left_col = False
    ajax_pagination = False
    use_datatables = True

    # override old class properties
    report_template_path = "reports/async/tabular.html"
    flush_layout = True

    @property
    def headers(self):
        """
            Override this method to create a functional tabular report.
            Returns a DataTablesHeader() object (or a list, but preferably the former.
        """
        return DataTablesHeader()

    @property
    def rows(self):
        """
            Override this method to create a functional tabular report.
            Returns 2D list of rows.
            [['row1'],[row2']]
        """
        return []

    @property
    def total_records(self):
        """
            Override for pagination.
            Returns an integer.
        """
        return 0

    @property
    def total_filtered_records(self):
        """
            Override for pagination.
            Returns an integer.
            return -1 if you want total_filtered_records to equal whatever the value of total_records is.
        """
        return -1

    @property
    def shared_pagination_GET_params(self):
        """
            Override.
            Should return a list of dicts with the name and value of the GET parameters
            that you'd like to pass to the server-side pagination.
            ex: [dict(name='group', value=self.group_name)]
        """
        return []

    @property
    def pagination_source(self):
        args = [self.domain] if self.domain else []
        return self.get_url(*args, **dict(render_as='json'))

    _pagination = None
    @property
    def pagination(self):
        if self._pagination is None:
            self._pagination = DatatablesParams.from_request_dict(self.request.REQUEST)
        return self._pagination

    @property
    def json_dict(self):
        """
            When you implement self.rows for a paginated report,
            it should take into consideration the following:
            self.pagination.start (skip)
            self.pagination.count (limit)
        """
        rows = self.rows
        total_records = self.total_records
        if not isinstance(total_records, int):
            raise ValueError("Property 'total_records' should return an int.")
        total_filtered_records = self.total_filtered_records
        if not isinstance(total_filtered_records, int):
            raise ValueError("Property 'total_filtered_records' should return an int.")
        return dict(
            sEcho=self.pagination.echo,
            iTotalRecords=total_records,
            iTotalDisplayRecords=total_filtered_records if total_filtered_records >= 0 else total_records,
            aaData=rows
        )

    @property
    def fixed_cols_spec(self):
        """
            Override
            Returns a dict formatted like:
            dict(num=<num_cols_to_fix>, width=<width_of_total_fixed_cols>)
        """
        return dict(num=1, width=200)

    @property
    def override_export_sheet_name(self):
        """
            Override the export sheet name here. Return a string.
        """
        return None

    _export_sheet_name = None
    @property
    def export_sheet_name(self):
        if self._export_sheet_name is None:
            override = self.override_export_sheet_name
            self._export_sheet_name = override if isinstance(override, str) else self.name
        return self._export_sheet_name

    @property
    def export_table(self):
        try:
            import xlwt
        except ImportError:
            raise Exception("It doesn't look like this machine is configured for "
                            "excel export. To export to excel you have to run the "
                            "command:  easy_install xlutils")
        headers = self.headers
        formatted_rows = self.rows

        def _unformat_row(row):
            return [col.get("sort_key", col) if isinstance(col, dict) else col for col in row]

        table = headers.as_table
        rows = [_unformat_row(row) for row in formatted_rows]
        table.extend(rows)
        if self.total_row:
            table.append(_unformat_row(self.total_row))

        return [[self.export_sheet_name, table]]

    @property
    def report_context(self):
        """
            Don't override.
            Override the properties headers and rows instead of this.
        """
        headers = self.headers
        if not (isinstance(headers, DataTablesHeader) or isinstance(headers, list)):
            raise ValueError("Property 'headers' should return a DataTablesHeader object or a list.")
        if isinstance(headers, list):
            raise DeprecationWarning("Property 'headers' should return a DataTablesHeader object, not a list.")

        if not self.ajax_pagination:
            rows = self.rows
            if not isinstance(rows, list):
                raise ValueError("Property 'rows' should return a list.")
        else:
            rows = []

        if self.total_row is not None and not isinstance(self.total_row, list):
            raise ValueError("'total_row' should be a list.")

        pagination_spec = dict(is_on=self.ajax_pagination)
        if self.ajax_pagination:
            shared_params = self.shared_pagination_GET_params
            if not isinstance(shared_params, list):
                raise ValueError("Property 'pagination_params' should return a list.")
            pagination_spec.update(
                params=shared_params,
                source=self.pagination_source,
                filter=False
            )

        left_col = dict(is_fixed=self.fix_left_col)
        if self.fix_left_col:
            spec = self.fixed_cols_spec
            if not isinstance(spec, dict):
                raise ValueError("Property 'fixed_cols_spec' should return a dict.")
            left_col.update(fixed=spec)

        return dict(
            report_table=dict(
                headers=headers,
                rows=rows,
                total_row=self.total_row,
                default_rows=self.default_rows,
                start_at_row=self.start_at_row,
                show_all_rows=self.show_all_rows,
                pagination=pagination_spec,
                left_col=left_col,
                datatables=self.use_datatables,
            )
        )

    def table_cell(self, value, html=None):
        return dict(
            sort_key=value,
            html="%s" % value if html is None else html
        )