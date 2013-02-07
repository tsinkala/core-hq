import logging
import pdb
from django.http import HttpResponse
from django.utils.decorators import method_decorator, classonlymethod
from django.views.decorators.csrf import csrf_protect
import simplejson
from corehq.apps.domain.decorators import login_and_domain_required
from dimagi.utils.decorators import inline
from corehq.elastic import get_es
from django.views.generic import View
from dimagi.utils.logging import notify_exception


DEFAULT_SIZE = 10

class ESView(View):
    """
    Generic CBV for interfacing with the Elasticsearch REST api.
    This is necessary because tastypie's built in REST assumptions don't like
    ES's POST for querying, which we can set explicitly here.

    For security purposes, queries ought to be domain'ed by the requesting user, so a base_query
    is encouraged to be added.

    Access to the APIs can be done via url endpoints which are attached to the corehq.api.urls

    or programmatically via the self.run_query() method.

    This current iteration of the ESView must require a domain for its usage for security purposes.
    """
    #note - for security purposes, csrf protection is ENABLED
    #search POST queries must take the following format:
    #query={query_json}
    #csrfmiddlewaretoken=token

    #in curl, this is:
    #curl -b "csrftoken=<csrftoken>;sessionid=<session_id>" -H "Content-Type: application/json" -XPOST http://server/a/domain/api/v0.1/xform_es/
    #     -d"query=@myquery.json&csrfmiddlewaretoken=<csrftoken>"
    #or, call this programmatically to avoid CSRF issues.

    index = ""
    domain = ""
    es = None

    http_method_names = ['get', 'post', 'head', ]

    def __init__(self, domain):
        self.domain=domain
        self.es = get_es()

    def head(self, *args, **kwargs):
        raise NotImplementedError("Not implemented")

    @method_decorator(login_and_domain_required)
    @method_decorator(csrf_protect)
    def dispatch(self, *args, **kwargs):
        req = args[0]
        self.pretty = req.GET.get('pretty', False)
        if self.pretty:
            self.indent = 4
        else:
            self.indent = None
        ret = super(ESView, self).dispatch(*args, **kwargs)
        return ret

    @classonlymethod
    def as_view(cls, **initkwargs):
        """
        Django as_view cannot be used since the constructor requires information only present in the request.
        """
        raise Exception('as_view not supported for domain-specific ESView')
        
    @classonlymethod
    def as_domain_specific_view(cls, **initkwargs):
        """
        Creates a simple domain-specific class-based view for passing through ES requests.
        """
        def view(request, domain, *args, **kwargs):
            self = cls(domain)
            return self.dispatch(request, domain, *args, **kwargs)
        
        return view

    def run_query(self, es_query):
        """
        Run a more advanced POST based ES query

        Returns the raw query json back, or None if there's an error
        """
        #todo: backend audit logging of all these types of queries
        if es_query.has_key('fields') or es_query.has_key('script_fields'):
            #nasty hack to add domain field to query that does specific fields.
            #do nothing if there's no field query because we get everything
            fields = es_query.get('fields', [])
            fields.append('domain')
            es_query['fields'] = fields

        es_results = self.es[self.index].get('_search', data=es_query)
        if es_results.has_key('error'):
            notify_exception(
                "Error in %s elasticsearch query: %s" % (self.index, es_results['error']))
            return None

        for res in es_results['hits']['hits']:
            res_domain = None
            if res.has_key('_source'):
                #check source
                res_domain = res['_source'].get('domain', None)
            elif res.has_key('fields'):
                res_domain = res['fields'].get('domain', None)
                #check fields
            assert res_domain == self.domain, "Security check failed, search result domain did not match requester domain: %s != %s" % (res_domain, self.domain)
        return es_results

    def base_query(self, terms={}, fields=[], start=0, size=DEFAULT_SIZE):
        """
        The standard query to run across documents of a certain index.
        domain = exact match domain string
        terms = k,v pairs of terms you want to match against. you can dive down into properties like form.foo for an xform, like { "username": "foo", "type": "bar" } - this will make it into a term: k: v dict
        fields = field properties to report back in the results['fields'] array. if blank, you will need to read the _source
        start = where to start the results from
        size = default size in ES is 10, also explicitly set here.
        """
        query = {
            "filter": {
                "and": [
                    {"term": {"domain.exact": self.domain}}
                ]
            },
            "from": start,
            "size": size
        }
        if len(fields) > 0:
            query['fields'] = fields
        for k, v in terms.items():
            query['filter']['and'].append({"term": {k: v}})
        return query

    def get(self, *args, **kwargs):
        """
        Very basic querying based upon GET parameters.
        todo: apply GET params as lucene query_string params to base_query
        """
        size = self.request.GET.get('size', DEFAULT_SIZE)
        start = self.request.GET.get('start', 0)
        query_results = self.run_query(self.base_query(start=start, size=size))
        query_output = simplejson.dumps(query_results, indent=self.indent)
        response = HttpResponse(query_output, content_type="application/json")
        return response

    def post(self, *args, **kwargs):
        """
        More powerful ES querying using POST params.
        """
        try:
            raw_post = self.request.raw_post_data
            raw_query = simplejson.loads(raw_post)
        except Exception, ex:
            content_response = dict(message="Error parsing query request", exception=ex.message)
            response = HttpResponse(status=406, content=simplejson.dumps(content_response))
            return response

        #ensure that the domain is filtered in implementation
        domain = self.request.domain
        query_results = self.run_query(raw_query)
        query_output = simplejson.dumps(query_results, indent=self.indent)
        response = HttpResponse(query_output, content_type="application/json")
        return response


class CaseES(ESView):
    """
    Expressive CaseES interface. Yes, this is redundant with pieces of the v0_1.py CaseAPI - todo to merge these applications
    Which this should be the final say on ES access for Casedocs
    """
    index = "hqcases"


class XFormES(ESView):
    index = "xforms"


    @classmethod
    def by_case_id_query(cls, domain, case_id, terms={}, date_field=None, startdate=None,
                         enddate=None, date_format='%Y-%m-%d'):
        """
        Run a case_id query on both case properties (supporting old and new) for xforms.

        datetime options onsubmission ranges possible too by passing datetime startdate or enddate

        args:
        domain: string domain, required exact
        case_id: string
        terms: k,v of additional filters to apply as terms and block of filter
        date_field: string property of the xform submission you want to do date filtering, be sure to make sure that the field in question is indexed as a datetime
        startdate, enddate: datetime interval values
        date_format: string of the date format to filter based upon, defaults to yyyy-mm-dd
        """
        query = {
            "query": {
                "filtered": {
                    "filter": {
                        "and": [
                            {"term": {"domain.exact": domain}},
                        ]
                    },
                    "query": {
                        "query_string": {
                            "query": "(form.case.case_id:%(case_id)s OR form.case.@case_id:%(case_id)s)" % dict(
                                case_id=case_id)
                        }
                    }
                }
            }
        }
        if date_field is not None:
            range_query = {
                "numeric_range": {
                    date_field: {}
                }
            }

            if startdate is not None:
                range_query['numeric_range'][date_field]["gte"] = startdate.strftime(date_format)
            if enddate is not None:
                range_query['numeric_range'][date_field]["lte"] = enddate.strftime(date_format)
            query['query']['filtered']['filter']['and'].append(range_query)

        for k, v in terms.items():
            query['query']['filtered']['filter']['and'].append({"term": {k: v}})
        return query