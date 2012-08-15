from _collections import defaultdict
import datetime
import dateutil
from django.core.urlresolvers import reverse
from django.http import Http404
from django.conf import settings
import pytz
import sys
from corehq.apps.reports import util
from corehq.apps.reports._global.inspect import CaseListReport
from corehq.apps.reports.calc import entrytimes
from corehq.apps.reports.datatables import DataTablesHeader, DataTablesColumn, DTSortType
from corehq.apps.reports.display import xmlns_to_name, FormType
from corehq.apps.reports.standard import StandardTabularHQReport, StandardHQReport, StandardDateHQReport, user_link_template, DATE_FORMAT
from couchforms.models import XFormInstance
from dimagi.utils.couch.database import get_db
from dimagi.utils.parsing import json_format_datetime, string_to_datetime
from dimagi.utils.decorators.memoized import memoized
from dimagi.utils.timezones import utils as tz_utils
from dimagi.utils.web import get_url_base


class MonitoringReportMixin(object):

    @classmethod
    def get_user_link(cls, domain, user):
        user_link = user_link_template % {"link": "%s%s" % (get_url_base(), reverse("report_dispatcher", args=[domain, CaseListReport.slug])),
                                          "user_id": user.user_id,
                                          "username": user.username_in_report}
        return util.format_datatables_data(text=user_link, sort_key=user.username_in_report)


class CaseActivityReport(StandardTabularHQReport, MonitoringReportMixin):
    """
    User    Last 30 Days    Last 60 Days    Last 90 Days   Active Clients              Inactive Clients
    danny   5 (25%)         10 (50%)        20 (100%)       17                          6
    (name)  (modified_since(x)/[active + closed_since(x)])  (open & modified_since(120)) (open & !modified_since(120))
    """
    name = 'Case Activity'
    slug = 'case_activity'
    fields = ['corehq.apps.reports.fields.FilterUsersField',
              'corehq.apps.reports.fields.CaseTypeField',
              'corehq.apps.reports.fields.GroupField']
    all_users = None
    display_data = ['percent']


    class Row(object):
        def __init__(self, report, user):
            self.report = report
            self.user = user

        def active_count(self):
            """Open clients seen in the last 120 days"""
            return self.report.get_number_cases(
                user_id=self.user.get_id,
                modified_after=self.report.utc_now - self.report.inactive,
                modified_before=self.report.utc_now,
                closed=False,
            )

        def inactive_count(self):
            """Open clients not seen in the last 120 days"""
            return self.report.get_number_cases(
                user_id=self.user.get_id,
                modified_before=self.report.utc_now - self.report.inactive,
                closed=False,
            )

        def modified_count(self, startdate=None, enddate=None):
            enddate = enddate or self.report.utc_now
            return self.report.get_number_cases(
                user_id=self.user.get_id,
                modified_after=startdate,
                modified_before=enddate,
            )

        def closed_count(self, startdate=None, enddate=None):
            enddate = enddate or self.report.utc_now
            return self.report.get_number_cases(
                user_id=self.user.get_id,
                modified_after=startdate,
                modified_before=enddate,
                closed=True
            )

        def header(self):
            return CaseActivityReport.get_user_link(self.report.domain, self.user)

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

    def get_parameters(self):
        landmarks_param = self.request_params.get('landmarks', [30,60,90])
        inactive_param = self.request_params.get('inactive', 120)
        self.display_data = self.request_params.get('display', ['percent'])
        if landmarks_param + [inactive_param] != sorted(landmarks_param + [inactive_param]):
            raise Http404()
        self.landmarks = [datetime.timedelta(days=l) for l in landmarks_param]
        self.inactive = datetime.timedelta(days=inactive_param)
        if self.history:
            self.now = self.history
        else:
            self.now = datetime.datetime.now(tz=self.timezone)

    @property
    @memoized
    def utc_now(self):
        return tz_utils.adjust_datetime_to_timezone(self.now, self.timezone.zone, pytz.utc.zone)

    def get_headers(self):
        headers = DataTablesHeader(DataTablesColumn("Users"))
        for landmark in self.landmarks:
            headers.add_column(DataTablesColumn("Last %s Days" % landmark.days if landmark else "Ever",
                sort_type=DTSortType.NUMERIC,
                help_text='Number of cases modified (or closed) in the last %s days' % landmark.days))
        headers.add_column(DataTablesColumn("Active Cases",
            sort_type=DTSortType.NUMERIC,
            help_text='Number of cases modified in the last %s days that are still open' % self.inactive.days))
        headers.add_column(DataTablesColumn("Inactive Cases",
            sort_type=DTSortType.NUMERIC,
            help_text="Number of cases that are open but haven't been touched in the last %s days" % self.inactive.days))
        return headers

    def get_rows(self):
        rows = [self.Row(self, user) for user in self.users]
        total_row = self.TotalRow(rows, "All Users")

        def format_row(row):
            cells = [row.header()]
            def add_numeric_cell(text, value=None):
                if value is None:
                    value = int(text)
                cells.append(util.format_datatables_data(text=text, sort_key=value))
            for landmark in self.landmarks:
                value = row.modified_count(self.utc_now - landmark)
                total = row.active_count() + row.closed_count(self.utc_now - landmark)

                try:
                    display = '%d (%d%%)' % (value, value * 100. / total)
                except ZeroDivisionError:
                    display = '%d' % value
                add_numeric_cell(display, value)
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


class SubmissionsByFormReport(StandardTabularHQReport, StandardDateHQReport, MonitoringReportMixin):
    name = "Submissions By Form"
    slug = "submissions_by_form"
    fields = ['corehq.apps.reports.fields.FilterUsersField',
              'corehq.apps.reports.fields.GroupField',
              'corehq.apps.reports.fields.DatespanField']
    fix_left_col = True

    def get_parameters(self):
        self.form_types = self.get_relevant_form_types()

    def get_headers(self):
        form_names = [xmlns_to_name(*id_tuple) for id_tuple in self.form_types]
        form_names = [name.replace("/", " / ") if name is not None else '(No name)' for name in form_names]

        if self.form_types:
            # this fails if form_names, form_types is [], []
            form_names, self.form_types = zip(*sorted(zip(form_names, self.form_types)))

        headers = DataTablesHeader(DataTablesColumn("User", span=3))
        for name in list(form_names):
            headers.add_column(DataTablesColumn(name, sort_type=DTSortType.NUMERIC))
        headers.add_column(DataTablesColumn("All Forms", sort_type=DTSortType.NUMERIC))

        return headers

    def get_rows(self):
        counts = self.get_submissions_by_form_json()
        rows = []
        totals_by_form = defaultdict(int)

        for user in self.users:
            row = []
            for form_type in self.form_types:
                userID = user.userID
                try:
                    count = counts[userID][form_type]
                    row.append(count)
                    totals_by_form[form_type] += count
                except Exception:
                    row.append(0)
            row_sum = sum(row)
            rows.append([self.get_user_link(self.domain, user)] + [util.format_datatables_data(row_data, row_data) for row_data in row] + [util.format_datatables_data("<strong>%s</strong>" % row_sum, row_sum)])

        totals_by_form = [totals_by_form[form_type] for form_type in self.form_types]
        self.total_row = ["All Users"] + ["%s" % t for t in totals_by_form] + ["<strong>%s</strong>" % sum(totals_by_form)]

        return rows

    def get_submissions_by_form_json(self):
        userIDs = [user.user_id for user in self.users]
        submissions = XFormInstance.view('reports/all_submissions',
            startkey=[self.domain, self.datespan.startdate_param_utc],
            endkey=[self.domain, self.datespan.enddate_param_utc],
            include_docs=True,
            reduce=False
        )
        counts = defaultdict(lambda: defaultdict(int))
        for sub in submissions:
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
                if (userIDs is None) or (userID in userIDs):
                    counts[userID][FormType(self.domain, sub['xmlns'], app_id).get_id_tuple()] += 1
        return counts

    def get_relevant_form_types(self):
        userIDs = [user.user_id for user in self.users]
        submissions = XFormInstance.view('reports/all_submissions',
            startkey=[self.domain, self.datespan.startdate_param_utc],
            endkey=[self.domain, self.datespan.enddate_param_utc],
            include_docs=True,
            reduce=False
        )
        form_types = set()

        for submission in submissions:
            try:
                xmlns = submission['xmlns']
            except KeyError:
                xmlns = None

            try:
                app_id = submission['app_id']
            except Exception:
                app_id = None

            if userIDs is not None:
                try:
                    userID = submission['form']['meta']['userID']
                except Exception:
                    pass
                else:
                    if userID in userIDs:
                        form_types.add(FormType(self.domain, xmlns, app_id).get_id_tuple())
            else:
                form_types.add(FormType(self.domain, xmlns, app_id).get_id_tuple())

        return sorted(form_types)


class DailyReport(StandardDateHQReport, StandardTabularHQReport, MonitoringReportMixin):
    couch_view = ''
    fix_left_col = True
    fields = ['corehq.apps.reports.fields.FilterUsersField',
              'corehq.apps.reports.fields.GroupField',
              'corehq.apps.reports.fields.DatespanField']

    def get_headers(self):
        self.dates = [self.datespan.startdate]
        while self.dates[-1] < self.datespan.enddate:
            self.dates.append(self.dates[-1] + datetime.timedelta(days=1))

        headers = DataTablesHeader(DataTablesColumn("Username", span=3))
        for d in self.dates:
            headers.add_column(DataTablesColumn(d.strftime(DATE_FORMAT), sort_type=DTSortType.NUMERIC))
        headers.add_column(DataTablesColumn("Total", sort_type=DTSortType.NUMERIC))
        return headers

    def get_rows(self):
        utc_dates = [tz_utils.adjust_datetime_to_timezone(date, self.timezone.zone, pytz.utc.zone) for date in self.dates]
        date_map = dict([(date.strftime(DATE_FORMAT), i+1) for (i,date) in enumerate(utc_dates)])

        key = [self.domain]
        results = get_db().view(
            self.couch_view,
            reduce=False,
            startkey=key+[self.datespan.startdate_param_utc],
            endkey=key+[self.datespan.enddate_param_utc]
        ).all()

        user_map = dict([(user.user_id, i) for (i, user) in enumerate(self.users)])
        userIDs = [user.user_id for user in self.users]
        rows = [[0]*(2+len(date_map)) for _ in range(len(self.users))]
        total_row = [0]*(2+len(date_map))

        for result in results:
            _, date = result['key']
            date = dateutil.parser.parse(date)
            tz_offset = self.timezone.localize(self.datespan.enddate).strftime("%z")
            date = date + datetime.timedelta(hours=int(tz_offset[0:3]), minutes=int(tz_offset[0]+tz_offset[3:5]))
            date = date.isoformat()
            val = result['value']
            user_id = val.get("user_id")
            if user_id in userIDs:
                date_key = date_map.get(date[0:10], None)
                if date_key:
                    rows[user_map[user_id]][date_key] += 1

        for i, user in enumerate(self.users):
            rows[i][0] = self.get_user_link(self.domain, user)
            total = sum(rows[i][1:-1])
            rows[i][-1] = total
            total_row[1:-1] = [total_row[ind+1]+val for ind, val in enumerate(rows[i][1:-1])]
            total_row[-1] += total

        total_row[0] = "All Users"
        self.total_row = total_row

        for row in rows:
            row[1:] = [util.format_datatables_data(val, val) for val in row[1:]]

        return rows


class DailySubmissionsReport(DailyReport):
    name = "Daily Form Submissions"
    slug = "daily_submissions"
    couch_view = 'reports/daily_submissions'

class DailyFormCompletionsReport(DailyReport):
    name = "Daily Form Completions"
    slug = "daily_completions"
    couch_view = 'reports/daily_completions'


class FormCompletionTrendsReport(StandardTabularHQReport, StandardDateHQReport, MonitoringReportMixin):
    name = "Form Completion Trends"
    slug = "completion_times"
    fields = ['corehq.apps.reports.fields.FilterUsersField',
              'corehq.apps.reports.fields.SelectFormField',
              'corehq.apps.reports.fields.GroupField',
              'corehq.apps.reports.fields.DatespanField']

    def get_headers(self):
        return DataTablesHeader(DataTablesColumn("User"),
            DataTablesColumn("Average duration"),
            DataTablesColumn("Shortest"),
            DataTablesColumn("Longest"),
            DataTablesColumn("No. of Forms"))

    def get_rows(self):
        form = self.request_params.get('form', '')
        rows = []

        if form:
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
                datadict = entrytimes.get_user_data(self.domain, user.user_id, form, self.datespan)
                rows.append([self.get_user_link(self.domain, user),
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


class SubmissionTimesReport(StandardHQReport):
    name = "Submission Times"
    slug = "submit_time_punchcard"
    fields = ['corehq.apps.reports.fields.FilterUsersField',
              'corehq.apps.reports.fields.SelectMobileWorkerField']
    template_name = "reports/async/basic.html"
    report_partial = "reports/partials/punchcard.html"
    show_time_notice = True

    def calc(self):
        data = defaultdict(lambda: 0)
        for user in self.users:
            startkey = [self.domain, user.user_id]
            endkey = [self.domain, user.user_id, {}]
            view = get_db().view("formtrends/form_time_by_user",
                startkey=startkey,
                endkey=endkey,
                group=True)
            for row in view:
                domain, _user, day, hour = row["key"]

                if hour and day:
                    #adjust to timezone
                    now = datetime.datetime.utcnow()
                    hour = int(hour)
                    day = int(day)
                    report_time = datetime.datetime(now.year, now.month, now.day, hour, tzinfo=pytz.utc)
                    report_time = tz_utils.adjust_datetime_to_timezone(report_time, pytz.utc.zone, self.timezone.zone)
                    hour = report_time.hour

                    data["%d %02d" % (day, hour)] = data["%d %02d" % (day, hour)] + row["value"]
        self.context["chart_url"] = self.generate_chart(data)

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

        day_names = "Sun Mon Tue Wed Thu Fri Sat".split(" ")
        days = (0, 6, 5, 4, 3, 2, 1)

        sizes=[]
        for d in days:
            sizes.extend([data["%d %02d" % (d, h)] for h in range(24)])
        sizes.extend([0] * 24)
        if no_data:
            # fill in a line out of view so that chart.get_url() doesn't crash
            sizes.extend([1] * 24)
        chart.add_data(sizes)

        chart.set_axis_labels('x', [''] + [str(h) for h  in range(24)] + [''])
        chart.set_axis_labels('y', [''] + [day_names[n] for n in days] + [''])

        chart.add_marker(1, 1.0, 'o', '333333', 25)
        return chart.get_url() + '&chds=-1,24,-1,7,0,20'


class SubmitDistributionReport(StandardHQReport):
    name = "Submit Distribution"
    slug = "submit_distribution"
    fields = ['corehq.apps.reports.fields.FilterUsersField',
              'corehq.apps.reports.fields.SelectMobileWorkerField']
    template_name = "reports/async/basic.html"
    report_partial = "reports/partials/generic_piechart.html"

    def calc(self):
        predata = {}
        data = []
        for user in self.users:
            startkey = ["u", self.domain, user.user_id]
            endkey = ["u", self.domain, user.user_id, {}]
            view = get_db().view("formtrends/form_type_by_user",
                startkey=startkey,
                endkey=endkey,
                group=True,
                reduce=True)
            for row in view:
                xmlns = row["key"][-1]
                form_name = xmlns_to_name(self.domain, xmlns, app_id=None)
                if form_name in predata:
                    predata[form_name]["value"] = predata[form_name]["value"] + row["value"]
                    predata[form_name]["description"] = "(%s) submissions of %s" %\
                                                        (predata[form_name]["value"], form_name)
                else:
                    predata[form_name] = {"display": form_name,
                                          "value": row["value"],
                                          "description": "(%s) submissions of %s" %\
                                                         (row["value"], form_name)}
        for value in predata.values():
            data.append(value)

        self.context.update({
            "chart_data": data,
            "user_id": self.individual,
            "graph_width": 900,
            "graph_height": 500
        })


class FormCompletionVsSubmissionTrendsReport(StandardTabularHQReport, StandardDateHQReport, MonitoringReportMixin):
    name = "Form Completion vs. Submission Trends"
    slug = "completion_vs_submission"
    fields = ['corehq.apps.reports.fields.FilterUsersField',
              'corehq.apps.reports.fields.SelectAllFormField',
              'corehq.apps.reports.fields.GroupField',
              'corehq.apps.reports.fields.SelectMobileWorkerField',
              'corehq.apps.reports.fields.DatespanField']

    def get_headers(self):
        return DataTablesHeader(DataTablesColumn("User", span=3),
            DataTablesColumn("Completion Time", span=2),
            DataTablesColumn("Submission Time", span=2),
            DataTablesColumn("View", sortable=False, span=2),
            DataTablesColumn("Difference", sort_type=DTSortType.NUMERIC, span=3)
        )

    def get_rows(self):
        rows = list()
        prefix = ["user"]
        selected_form = self.request_params.get('form')
        if selected_form:
            prefix.append("form_type")
        total = 0
        total_seconds = 0
        for user in self.users:
            key = [" ".join(prefix), self.domain, user.userID]
            if selected_form:
                key.append(selected_form)
            data = get_db().view("reports/completion_vs_submission",
                startkey=key+[self.datespan.startdate_param_utc],
                endkey=key+[self.datespan.enddate_param_utc],
                reduce=False
            ).all()
            for item in data:
                vals = item.get('value')
                completion_time = dateutil.parser.parse(vals.get('completion_time'))
                completion_time = completion_time.replace(tzinfo=pytz.utc)
                submission_time = dateutil.parser.parse(vals.get('submission_time'))
                submission_time = submission_time.replace(tzinfo=pytz.utc)
                td = submission_time-completion_time

                DFORMAT  = "%d %b %Y, %H:%M"
                td_total = (td.seconds + td.days * 24 * 3600)

                rows.append([
                    self.get_user_link(self.domain, user),
                    completion_time.strftime(DFORMAT),
                    submission_time.strftime(DFORMAT),
                    self.view_form_link(item.get('id', '')),
                    util.format_datatables_data(text=self.format_td_status(td), sort_key=td_total)
                ])

                if td_total >= 0:
                    total_seconds += td_total
                    total += 1

        self.total_row = ["Average", "-", "-", "-", self.format_td_status(int(total_seconds/total), False) if total > 0 else "--"]
        return rows

    def format_td_status(self, td, use_label=True):
        status = list()
        template = '<span class="label %(klass)s">%(status)s</span>'
        klass = ""
        if isinstance(td, int):
            td = datetime.timedelta(seconds=td)
        if isinstance(td, datetime.timedelta):
            hours = td.seconds//3600
            minutes = (td.seconds//60)%60
            vals = [td.days, hours, minutes, (td.seconds - hours*3600 - minutes*60)]
            names = ["day", "hour", "minute", "second"]
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
                status = ["submitted before completed [strange]"]
                klass = "label-inverse"

        if use_label:
            return template % dict(status=", ".join(status), klass=klass)
        else:
            return ", ".join(status)

    def view_form_link(self, instance_id):
        return '<a class="btn" href="%s">View Form</a>' % reverse('render_form_data', args=[self.domain, instance_id])