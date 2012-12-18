from _collections import defaultdict
import datetime
import logging
import dateutil
from django.core.urlresolvers import reverse
from django.http import Http404
from django.conf import settings
from django.utils.safestring import mark_safe
import pytz
import sys
from corehq.apps.domain.models import Domain
from corehq.apps.groups.models import Group
from corehq.apps.reports import util
from corehq.apps.reports.standard import ProjectReportParametersMixin, \
    DatespanMixin, ProjectReport, DATE_FORMAT
from corehq.apps.reports.calc import entrytimes
from corehq.apps.reports.datatables import DataTablesHeader, DataTablesColumn, DTSortType, DataTablesColumnGroup
from corehq.apps.reports.decorators import cache_report
from corehq.apps.reports.display import xmlns_to_name, FormType
from corehq.apps.reports.generic import GenericTabularReport
from couchforms.models import XFormInstance
from dimagi.utils.couch.database import get_db
from dimagi.utils.decorators.memoized import memoized
from dimagi.utils.parsing import json_format_datetime
from dimagi.utils.timezones import utils as tz_utils
from dimagi.utils.web import get_url_base
from django.utils.translation import ugettext as _
from django.utils.translation import ugettext_noop

def cache_report():
    """do nothing until the real cache_report is fixed"""
    def _fn(fn):
        return fn
    return _fn

monitoring_report_cacher = cache_report()

class WorkerMonitoringReportTable(GenericTabularReport, ProjectReport, ProjectReportParametersMixin):
    """
        # todo doc.
    """
    exportable = True

    def get_user_link(self, user):
        user_link_template = '<a href="%(link)s?individual=%(user_id)s">%(username)s</a>'
        from corehq.apps.reports.standard.inspect import CaseListReport
        user_link = user_link_template % {"link": "%s%s" % (get_url_base(),
                                                            CaseListReport.get_url(self.domain)),
                                          "user_id": user.get('user_id'),
                                          "username": user.get('username_in_report')}
        return self.table_cell(user.get('raw_username'), user_link)

    @property
    @monitoring_report_cacher
    def report_context(self):
        return super(WorkerMonitoringReportTable, self).report_context

    @property
    @monitoring_report_cacher
    def export_table(self):
        return super(WorkerMonitoringReportTable, self).export_table


class WorkerMonitoringChart(ProjectReport, ProjectReportParametersMixin):
    """
        #todo doc
    """
    fields = ['corehq.apps.reports.fields.FilterUsersField',
              'corehq.apps.reports.fields.SelectMobileWorkerField']
    flush_layout = True
    report_template_path = "reports/async/basic.html"


class CaseActivityReport(WorkerMonitoringReportTable):
    """
    todo move this to the cached version when ready
    User    Last 30 Days    Last 60 Days    Last 90 Days   Active Clients              Inactive Clients
    danny   5 (25%)         10 (50%)        20 (100%)       17                          6
    (name)  (modified_since(x)/[active + closed_since(x)])  (open & modified_since(120)) (open & !modified_since(120))
    """
    name = ugettext_noop('Case Activity')
    slug = 'case_activity'
    fields = ['corehq.apps.reports.fields.FilterUsersField',
              'corehq.apps.reports.fields.CaseTypeField',
              'corehq.apps.reports.fields.GroupField']
    all_users = None
    display_data = ['percent']
    emailable = True
    special_notice = ugettext_noop("This report currently does not support case sharing. "
                       "There might be inconsistencies in case totals if the user is part of a case sharing group. "
                       "We are working to correct this shortly.")


    class Row(object):
        def __init__(self, report, user):
            self.report = report
            self.user = user

        @memoized
        def active_count(self):
            """Open clients seen in the last 120 days"""
            return self.report.get_number_cases(
                user_id=self.user.get('user_id'),
                modified_after=self.report.utc_now - self.report.milestone,
                modified_before=self.report.utc_now,
                closed=False,
            )

        @memoized
        def inactive_count(self):
            """Open clients not seen in the last 120 days"""
            return self.report.get_number_cases(
                user_id=self.user.get('user_id'),
                modified_before=self.report.utc_now - self.report.milestone,
                closed=False,
            )

        def modified_count(self, startdate=None, enddate=None):
            enddate = enddate or self.report.utc_now
            return self.report.get_number_cases(
                user_id=self.user.get('user_id'),
                modified_after=startdate,
                modified_before=enddate,
            )

        def closed_count(self, startdate=None, enddate=None):
            enddate = enddate or self.report.utc_now
            return self.report.get_number_cases(
                user_id=self.user.get('user_id'),
                modified_after=startdate,
                modified_before=enddate,
                closed=True
            )

        def header(self):
            return self.report.get_user_link(self.user)

    class TotalRow(object):
        def __init__(self, rows, header):
            self.rows = rows
            self._header = header

        def active_count(self):
            return sum([row.active_count() for row in self.rows])

        def inactive_count(self):
            return sum([row.inactive_count() for row in self.rows])

        def modified_count(self, startdate=None, enddate=None):
            return sum([row.modified_count(startdate, enddate) for row in self.rows])

        def closed_count(self, startdate=None, enddate=None):
            return sum([row.closed_count(startdate, enddate) for row in self.rows])

        def header(self):
            return self._header

    _default_landmarks = [30, 60, 90]
    @property
    @memoized
    def landmarks(self):
        landmarks_param = self.request_params.get('landmarks')
        landmarks_param = landmarks_param if isinstance(landmarks_param, list) else []
        landmarks_param = [param for param in landmarks_param if isinstance(param, int)]
        landmarks = landmarks_param if landmarks_param else self._default_landmarks
        return [datetime.timedelta(days=l) for l in landmarks]

    _default_milestone = 120
    @property
    @memoized
    def milestone(self):
        milestone_param = self.request_params.get('milestone')
        milestone_param = milestone_param if isinstance(milestone_param, int) else None
        milestone = milestone_param if milestone_param else self._default_milestone
        return datetime.timedelta(days=milestone)

    @property
    @memoized
    def utc_now(self):
        return tz_utils.adjust_datetime_to_timezone(datetime.datetime.utcnow(), self.timezone.zone, pytz.utc.zone)

    @property
    def headers(self):
        columns = [DataTablesColumn(_("Users"))]
        for landmark in self.landmarks:
            num_cases = DataTablesColumn(_("# Modified or Closed"), sort_type=DTSortType.NUMERIC,
                help_text=_("The number of cases that have been modified between %d days ago and today." % landmark.days)
            )
            proportion = DataTablesColumn(_("Proportion"), sort_type=DTSortType.NUMERIC,
                help_text=_("The number of modified cases / (#active + #closed cases).")
            )
            columns.append(DataTablesColumnGroup(_("Cases in Last %s Days") % landmark.days if landmark else _("Ever"),
                num_cases,
                proportion
            ))
        columns.append(DataTablesColumn(_("# Active Cases"),
            sort_type=DTSortType.NUMERIC,
            help_text=_('Number of cases modified in the last %s days that are still open') % self.milestone.days))
        columns.append(DataTablesColumn(_("# Inactive Cases"),
            sort_type=DTSortType.NUMERIC,
            help_text=_("Number of cases that are open but haven't been touched in the last %s days") % self.milestone.days))
        return DataTablesHeader(*columns)

    @property
    def rows(self):
        rows = [self.Row(self, user) for user in self.users]

        total_row = self.TotalRow(rows, _("All Users"))

        def format_row(row):
            cells = [row.header()]

            def add_numeric_cell(text, value=None):
                if value is None:
                    try:
                        value = int(text)
                    except ValueError:
                        value = text
                cells.append(util.format_datatables_data(text=text, sort_key=value))

            for landmark in self.landmarks:
                value = row.modified_count(self.utc_now - landmark)
                total = row.active_count() + row.closed_count(self.utc_now - landmark)

                try:
                    p_val = float(value) * 100. / float(total)
                    proportion = '%.f%%' % p_val
                except ZeroDivisionError:
                    p_val = None
                    proportion = '--'
                add_numeric_cell(value, value)
                add_numeric_cell(proportion, p_val)

            add_numeric_cell(row.active_count())
            add_numeric_cell(row.inactive_count())
            return cells

        self.total_row = format_row(total_row)
        return map(format_row, rows)

    def get_number_cases(self, user_id, modified_after=None, modified_before=None, closed=None):
        key = [self.domain, {} if closed is None else closed, self.case_type or {}, user_id]

        if modified_after is None:
            start = ""
        else:
            start = json_format_datetime(modified_after)

        if modified_before is None:
            end = {}
        else:
            end = json_format_datetime(modified_before)

        return get_db().view('case/by_date_modified',
            startkey=key + [start],
            endkey=key + [end],
            group=True,
            group_level=0,
            wrapper=lambda row: row['value']
        ).one() or 0


class SubmissionsByFormReport(WorkerMonitoringReportTable, DatespanMixin):
    name = ugettext_noop("Submissions By Form")
    slug = "submissions_by_form"
    fields = ['corehq.apps.reports.fields.FilterUsersField',
                'corehq.apps.reports.fields.GroupField',
                'corehq.apps.reports.fields.DatespanField']
    fix_left_col = True
    emailable = True

    _form_types = None
    @property
    def form_types(self):
        if self._form_types is None:
            form_types = self._get_form_types()
            self._form_types = form_types if form_types else set()
        return self._form_types

    _all_submissions = None
    @property
    def all_submissions(self):
        if self._all_submissions is None:
            self._all_submissions = XFormInstance.view('reports/all_submissions',
                startkey=[self.domain, self.datespan.startdate_param_utc],
                endkey=[self.domain, self.datespan.enddate_param_utc],
                include_docs=True,
                reduce=False
            )
        return self._all_submissions

    @property
    def headers(self):
        form_names = [xmlns_to_name(*id_tuple) for id_tuple in self.form_types]
        form_names = [name.replace("/", " / ") if name is not None else _('(No name)') for name in form_names]
        if self.form_types:
            # this fails if form_names, form_types is [], []
            form_names, self._form_types = zip(*sorted(zip(form_names, self.form_types)))

        headers = DataTablesHeader(DataTablesColumn(_("User"), span=3))
        for name in list(form_names):
            headers.add_column(DataTablesColumn(name, sort_type=DTSortType.NUMERIC))
        headers.add_column(DataTablesColumn(_("All Forms"), sort_type=DTSortType.NUMERIC))
        return headers

    @property
    def rows(self):
        counts = self._get_form_counts()
        rows = []
        totals_by_form = defaultdict(int)
        for user in self.users:
            row = []
            for form_type in self.form_types:
                try:
                    count = counts[user.get('user_id')][form_type]
                    row.append(count)
                    totals_by_form[form_type] += count
                except Exception:
                    row.append(0)
            row_sum = sum(row)
            rows.append([self.get_user_link(user)] + \
                        [self.table_cell(row_data) for row_data in row] + \
                        [self.table_cell(row_sum, "<strong>%s</strong>" % row_sum)])

        totals_by_form = [totals_by_form[form_type] for form_type in self.form_types]
        self.total_row = [_("All Users")] + \
                         ["%s" % t for t in totals_by_form] + \
                         ["<strong>%s</strong>" % sum(totals_by_form)]
        return rows

    def _get_form_types(self):
        form_types = set()
        for submission in self.all_submissions:
            try:
                xmlns = submission['xmlns']
            except KeyError:
                xmlns = None

            try:
                app_id = submission['app_id']
            except Exception:
                app_id = None

            if self.user_ids:
                try:
                    userID = submission['form']['meta']['userID']
                except Exception:
                    pass
                else:
                    if userID in self.user_ids:
                        form_types.add(FormType(self.domain, xmlns, app_id).get_id_tuple())
            else:
                form_types.add(FormType(self.domain, xmlns, app_id).get_id_tuple())

        return sorted(form_types)

    def _get_form_counts(self):
        counts = defaultdict(lambda: defaultdict(int))
        for sub in self.all_submissions:
            try:
                app_id = sub['app_id']
            except Exception:
                app_id = None
            try:
                userID = sub['form']['meta']['userID']
            except Exception:
                # if a form don't even have a userID, don't even bother tryin'
                pass
            else:
                if userID in self.user_ids:
                    counts[userID][FormType(self.domain, sub['xmlns'], app_id).get_id_tuple()] += 1
        return counts


class DailyReport(WorkerMonitoringReportTable, DatespanMixin):
    # overrides
    fix_left_col = True
    fields = ['corehq.apps.reports.fields.FilterUsersField',
              'corehq.apps.reports.fields.GroupField',
              'corehq.apps.reports.fields.DatespanField']

    # new class properties
    dates_in_utc = True
    couch_view = None
    emailable = True

    _dates = None
    @property
    def dates(self):
        if self._dates is None:
            date_list = [self.datespan.startdate]
            while date_list[-1] < self.datespan.enddate:
                date_list.append(date_list[-1] + datetime.timedelta(days=1))
            self._dates = date_list
        return self._dates

    @property
    def headers(self):
        headers = DataTablesHeader(DataTablesColumn(_("Username"), span=3))
        for d in self.dates:
            headers.add_column(DataTablesColumn(d.strftime(DATE_FORMAT), sort_type=DTSortType.NUMERIC))
        headers.add_column(DataTablesColumn(_("Total"), sort_type=DTSortType.NUMERIC))
        return headers

    @property
    def rows(self):
        if self.dates_in_utc:
            _dates = [tz_utils.adjust_datetime_to_timezone(date, self.timezone.zone, pytz.utc.zone) for date in self.dates]
        else:
            _dates = self.dates

        key = [self.domain]
        results = get_db().view(
            self.couch_view,
            reduce=False,
            startkey=key+[self.datespan.startdate_param_utc if self.dates_in_utc else self.datespan.startdate_param],
            endkey=key+[self.datespan.enddate_param_utc if self.dates_in_utc else self.datespan.enddate_param]
        ).all()

        user_map = dict([(user.get('user_id'), i) for (i, user) in enumerate(self.users)])
        date_map = dict([(date.strftime(DATE_FORMAT), i+1) for (i,date) in enumerate(self.dates)])
        rows = [[0]*(2+len(date_map)) for _tmp in range(len(self.users))]
        total_row = [0]*(2+len(date_map))

        for result in results:
            _tmp, date = result['key']
            date = dateutil.parser.parse(date)
            tz_offset = self.timezone.localize(self.datespan.enddate).strftime("%z")
            date = date + datetime.timedelta(hours=int(tz_offset[0:3]), minutes=int(tz_offset[0]+tz_offset[3:5]))
            date = date.isoformat()
            val = result['value']
            user_id = val.get("user_id")
            if user_id in self.user_ids:
                date_key = date_map.get(date[0:10], None)
                if date_key:
                    rows[user_map[user_id]][date_key] += 1

        for i, user in enumerate(self.users):
            rows[i][0] = self.get_user_link(user)
            total = sum(rows[i][1:-1])
            rows[i][-1] = total
            total_row[1:-1] = [total_row[ind+1]+val for ind, val in enumerate(rows[i][1:-1])]
            total_row[-1] += total

        total_row[0] = _("All Users")
        self.total_row = total_row

        for row in rows:
            row[1:] = [self.table_cell(val) for val in row[1:]]
        return rows


class DailySubmissionsReport(DailyReport):
    name = ugettext_noop("Daily Form Submissions")
    slug = "daily_submissions"

    couch_view = 'reports/daily_submissions'


class DailyFormCompletionsReport(DailyReport):
    name = ugettext_noop("Daily Form Completions")
    slug = "daily_completions"

    couch_view = 'reports/daily_completions'
    dates_in_utc = False


class FormCompletionTrendsReport(WorkerMonitoringReportTable, DatespanMixin):
    name = ugettext_noop("Form Completion Trends")
    slug = "completion_times"
    fields = ['corehq.apps.reports.fields.FilterUsersField',
              'corehq.apps.reports.fields.SelectFormField',
              'corehq.apps.reports.fields.GroupField',
              'corehq.apps.reports.fields.DatespanField']

    @property
    def headers(self):
        return DataTablesHeader(DataTablesColumn(_("User")),
            DataTablesColumn(_("Average duration")),
            DataTablesColumn(_("Shortest")),
            DataTablesColumn(_("Longest")),
            DataTablesColumn(_("No. of Forms")))

    @property
    def rows(self):
        form = self.request_params.get('form', '')
        rows = []
        if not form:
            return rows

        totalsum = totalcount = 0
        def to_minutes(val_in_ms, d=None):
            if val_in_ms is None or d == 0:
                return None
            elif d:
                val_in_ms /= d
            return datetime.timedelta(seconds=int((val_in_ms + 500)/1000))

        globalmin = sys.maxint
        globalmax = 0
        for user in self.users:
            datadict = entrytimes.get_user_data(self.domain, user.get('user_id'), form, self.datespan)
            rows.append([self.get_user_link(user),
                         to_minutes(float(datadict["sum"]), float(datadict["count"])),
                         to_minutes(datadict["min"]),
                         to_minutes(datadict["max"]),
                         datadict["count"]
            ])
            totalsum = totalsum + datadict["sum"]
            totalcount = totalcount + datadict["count"]
            if datadict['min'] is not None:
                globalmin = min(globalmin, datadict["min"])
            if datadict['max'] is not None:
                globalmax = max(globalmax, datadict["max"])

        if totalcount:
            self.total_row = ["Total",
                              to_minutes(float(totalsum), float(totalcount)),
                              to_minutes(globalmin),
                              to_minutes(globalmax),
                              totalcount]
        return rows


class FormCompletionVsSubmissionTrendsReport(WorkerMonitoringReportTable, DatespanMixin):
    name = ugettext_noop("Form Completion vs. Submission Trends")
    slug = "completion_vs_submission"
    
    fields = ['corehq.apps.reports.fields.FilterUsersField',
              'corehq.apps.reports.fields.SelectAllFormField',
              'corehq.apps.reports.fields.GroupField',
              'corehq.apps.reports.fields.SelectMobileWorkerField',
              'corehq.apps.reports.fields.DatespanField']

    @property
    def headers(self):
        return DataTablesHeader(DataTablesColumn(_("User"), span=3),
            DataTablesColumn(_("Completion Time"), span=2),
            DataTablesColumn(_("Submission Time"), span=2),
            DataTablesColumn(_("View"), sortable=False, span=2),
            DataTablesColumn(_("Difference"), sort_type=DTSortType.NUMERIC, span=3)
        )

    @property
    def rows(self):
        rows = list()
        prefix = ["user"]
        selected_form = self.request_params.get('form')
        if selected_form:
            prefix.append("form_type")
        total = 0
        total_seconds = 0
        for user in self.users:
            key = [" ".join(prefix), self.domain, user.get('user_id')]
            if selected_form:
                key.append(selected_form)
            data = get_db().view("reports/completion_vs_submission",
                startkey=key+[self.datespan.startdate_param_utc],
                endkey=key+[self.datespan.enddate_param_utc],
                reduce=False
            ).all()
            for item in data:
                vals = item.get('value')
                completion_time = dateutil.parser.parse(vals.get('completion_time')).replace(tzinfo=None)
                completion_dst = False if self.timezone == pytz.utc else\
                tz_utils.is_timezone_in_dst(self.timezone, completion_time)
                completion_time = self.timezone.localize(completion_time, is_dst=completion_dst)
                submission_time = dateutil.parser.parse(vals.get('submission_time'))
                submission_time = submission_time.replace(tzinfo=pytz.utc)
                submission_time = tz_utils.adjust_datetime_to_timezone(submission_time, pytz.utc.zone, self.timezone.zone)
                td = submission_time-completion_time

                td_total = (td.seconds + td.days * 24 * 3600)
                rows.append([
                    self.get_user_link(user),
                    self._format_date(completion_time),
                    self._format_date(submission_time),
                    self._view_form_link(item.get('id', '')),
                    self.table_cell(td_total, self._format_td_status(td))
                ])

                if td_total >= 0:
                    total_seconds += td_total
                    total += 1

        self.total_row = [_("Average"), "-", "-", "-", self._format_td_status(int(total_seconds/total), False) if total > 0 else "--"]
        return rows

    def _format_date(self, date, d_format="%d %b %Y, %H:%M:%S"):
        return self.table_cell(
            date,
            "%s (%s)" % (date.strftime(d_format), date.tzinfo._tzname)
        )

    def _format_td_status(self, td, use_label=True):
        status = list()
        template = '<span class="label %(klass)s">%(status)s</span>'
        klass = ""
        if isinstance(td, int):
            td = datetime.timedelta(seconds=td)
        if isinstance(td, datetime.timedelta):
            hours = td.seconds//3600
            minutes = (td.seconds//60)%60
            vals = [td.days, hours, minutes, (td.seconds - hours*3600 - minutes*60)]
            names = [_("day"), _("hour"), _("minute"), _("second")]
            status = ["%s %s%s" % (val, names[i], "s" if val != 1 else "") for (i, val) in enumerate(vals) if val > 0]

            if td.days > 1:
                klass = "label-important"
            elif td.days == 1:
                klass = "label-warning"
            elif hours > 5:
                klass = "label-info"
            if not status:
                status.append("same")
            elif td.days < 0:
                status = [_("submitted before completed [strange]")]
                klass = "label-inverse"

        if use_label:
            return template % dict(status=", ".join(status), klass=klass)
        else:
            return ", ".join(status)

    def _view_form_link(self, instance_id):
        return '<a class="btn" href="%s">View Form</a>' % reverse('render_form_data', args=[self.domain, instance_id])



class SubmissionTimesReport(WorkerMonitoringChart):
    name = ugettext_noop("Submission Times")
    slug = "submit_time_punchcard"

    report_partial_path = "reports/partials/punchcard.html"
    show_time_notice = True

    @property
    @monitoring_report_cacher
    def report_context(self):
        data = defaultdict(int)
        for user in self.users:
            startkey = [self.domain, user.get('user_id')]
            endkey = [self.domain, user.get('user_id'), {}]
            view = get_db().view("formtrends/form_time_by_user",
                startkey=startkey,
                endkey=endkey,
                group=True)

            for row in view:
                _, _, day, hour = row["key"]

                if hour is not None and day is not None:
                    #adjust to timezone
                    now = datetime.datetime.utcnow()
                    report_time = datetime.datetime(now.year, now.month, now.day, hour, tzinfo=pytz.utc)
                    report_time = tz_utils.adjust_datetime_to_timezone(report_time, pytz.utc.zone, self.timezone.zone)
                    hour = report_time.hour
                    day += report_time.day - now.day

                    data[(day, hour)] += row["value"]
        return dict(
            chart_url=self.generate_chart(data),
            timezone=self.timezone,
        )

    @classmethod
    def generate_chart(cls, data, width=950, height=300):
        """
            Gets a github style punchcard chart.
            Hat tip: http://github.com/dustin/bindir/blob/master/gitaggregates.py
        """
        no_data = not data
        try:
            from pygooglechart import ScatterChart
        except ImportError:
            raise Exception("""Aw shucks, someone forgot to install the google chart library
on this machine and the report needs it. To get it, run
easy_install pygooglechart.  Until you do that this won't work.
""")

        chart = ScatterChart(width, height, x_range=(-1, 24), y_range=(-1, 7))

        chart.add_data([(h % 24) for h in range(24 * 8)])

        d=[]
        for i in range(8):
            d.extend([i] * 24)
        chart.add_data(d)

        # mapping between numbers 0..6 and its day of the week label
        day_names = "Sun Mon Tue Wed Thu Fri Sat".split(" ")
        # the order, bottom-to-top, in which the days should appear
        # i.e. Sun, Sat, Fri, Thu, etc
        days = (0, 6, 5, 4, 3, 2, 1)

        sizes=[]
        for d in days:
            sizes.extend([data[(d, h)] for h in range(24)])
        sizes.extend([0] * 24)
        if no_data:
            # fill in a line out of view so that chart.get_url() doesn't crash
            sizes.extend([1] * 24)
        chart.add_data(sizes)

        chart.set_axis_labels('x', [''] + [str(h) for h  in range(24)] + [''])
        chart.set_axis_labels('y', [''] + [day_names[n] for n in days] + [''])

        chart.add_marker(1, 1.0, 'o', '333333', 25)
        return chart.get_url() + '&chds=-1,24,-1,7,0,20'


class SubmitDistributionReport(WorkerMonitoringChart):
    name = ugettext_noop("Submit Distribution")
    slug = "submit_distribution"

    report_partial_path = "reports/partials/generic_piechart.html"

    @property
    @monitoring_report_cacher
    def report_context(self):
        predata = {}
        data = []
        for user in self.users:
            startkey = ["u", self.domain, user.get('user_id')]
            endkey = ["u", self.domain, user.get('user_id'), {}]
            view = get_db().view("formtrends/form_type_by_user",
                startkey=startkey,
                endkey=endkey,
                group=True,
                reduce=True)
            for row in view:
                xmlns = row["key"][-1]
                form_name = xmlns_to_name(self.domain, xmlns, app_id=None)
                def _desc(amt, form_name):
                    return _("(%(amt)s) submissions of %(form)s") % {
                        "amt": _(str(amt)), 
                        "form": _(form_name)
                    }
                if form_name in predata:
                    predata[form_name]["value"] = predata[form_name]["value"] + row["value"]
                    predata[form_name]["description"] = _desc(predata[form_name]["value"], 
                                                              form_name)
                else:
                    predata[form_name] = {"display": form_name,
                                          "value": row["value"],
                                          "description": _desc(row["value"], form_name)}
        for value in predata.values():
            data.append(value)
        return dict(
            chart_data=data,
            user_id=self.individual,
            graph_width=900,
            graph_height=500
        )
