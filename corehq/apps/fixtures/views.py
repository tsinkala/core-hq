import json
import logging
import csv
from corehq.apps.domain.decorators import login_and_domain_required
from corehq.apps.fixtures.models import FixtureDataType, FixtureDataItem
from corehq.apps.groups.models import Group
from corehq.apps.users.decorators import require_permission
from corehq.apps.users.models import Permissions, CommCareUser
from corehq.apps.users.util import normalize_username
from dimagi.utils.excel import WorkbookJSONReader
from dimagi.utils.web import json_response, render_to_response
from dimagi.utils.decorators.view import get_file
from django.contrib import messages
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseRedirect
from django.utils.decorators import method_decorator
from django.views.generic.base import TemplateView


require_can_edit_fixtures = require_permission(Permissions.EDIT_DATA)

def strip_json(obj, disallow_basic=None, disallow=None):
    disallow = disallow or []
    if disallow_basic is None:
        disallow_basic = ['_rev', 'domain', 'doc_type']
    disallow += disallow_basic
    ret = {}
    try:
        obj = obj.to_json()
    except Exception:
        pass
    for key in obj:
        if key not in disallow:
            ret[key] = obj[key]

    return ret

@require_can_edit_fixtures
def data_types(request, domain, data_type_id):
    if data_type_id:
        data_type = FixtureDataType.get(data_type_id)

        assert(data_type.doc_type == FixtureDataType._doc_type)
        assert(data_type.domain == domain)

        if request.method == 'GET':
            return json_response(strip_json(data_type))

        elif request.method == 'PUT':
            new = FixtureDataType(domain=domain, **json.load(request))
            for attr in 'tag', 'name', 'fields':
                setattr(data_type, attr, getattr(new, attr))
            data_type.save()
            return json_response(strip_json(data_type))

        elif request.method == 'DELETE':
            for item in FixtureDataItem.by_data_type(domain, data_type.get_id):
                item.delete()
            data_type.delete()
            return json_response({})

    elif data_type_id is None:

        if request.method == 'POST':
            data_type = FixtureDataType(domain=domain, **json.load(request))
            data_type.save()
            return json_response(strip_json(data_type))

        elif request.method == 'GET':
            return json_response([strip_json(x) for x in FixtureDataType.by_domain(domain)])

    return HttpResponseBadRequest()


def prepare_user(user):
    user.username = user.raw_username
    return strip_json(user, disallow=['password'])

@require_can_edit_fixtures
def data_items(request, domain, data_type_id, data_item_id):

    def prepare_item(item):
        ret = strip_json(item, disallow=['data_type_id'])
        if request.GET.get('groups') == 'true':
            ret['groups'] = []
            for group in item.get_groups():
                ret['groups'].append(strip_json(group))
        if request.GET.get('users') == 'true':
            ret['users'] = []
            for user in item.get_users():
                ret['users'].append(prepare_user(user))
        return ret

    if request.method == 'POST' and data_item_id is None:
        o = FixtureDataItem(domain=domain, data_type_id=data_type_id, **json.load(request))
        o.save()
        return json_response(strip_json(o, disallow=['data_type_id']))
    elif request.method == 'GET' and data_item_id is None:
        return json_response([prepare_item(x) for x in FixtureDataItem.by_data_type(domain, data_type_id)])
    elif request.method == 'GET' and data_item_id:
        o = FixtureDataItem.get(data_item_id)
        assert(o.domain == domain and o.data_type.get_id == data_type_id)
        return json_response(prepare_item(o))
    elif request.method == 'PUT' and data_item_id:
        original = FixtureDataItem.get(data_item_id)
        new = FixtureDataItem(domain=domain, **json.load(request))
        for attr in 'fields',:
            setattr(original, attr, getattr(new, attr))
        original.save()
        return json_response(strip_json(original, disallow=['data_type_id']))
    elif request.method == 'DELETE' and data_item_id:
        o = FixtureDataItem.get(data_item_id)
        assert(o.domain == domain and o.data_type.get_id == data_type_id)
        o.delete()
        return json_response({})
    else:
        return HttpResponseBadRequest()

def data_item_groups(request, domain, data_type_id, data_item_id, group_id):
    data_type = FixtureDataType.get(data_type_id)
    data_item = FixtureDataItem.get(data_item_id)
    group = Group.get(group_id)
    assert(data_type.doc_type == FixtureDataType._doc_type)
    assert(data_type.domain == domain)
    assert(data_item.doc_type == FixtureDataItem._doc_type)
    assert(data_item.domain == domain)
    assert(data_item.data_type_id == data_type_id)
    assert(group.doc_type == Group._doc_type)
    assert(group.domain == domain)

    print request.method

    if request.method == 'POST':
        data_item.add_group(group)
        return json_response({})
    elif request.method == 'DELETE':
        data_item.remove_group(group)
        return json_response({})
    else:
        return HttpResponseBadRequest()

def data_item_users(request, domain, data_type_id, data_item_id, user_id):
    data_type = FixtureDataType.get(data_type_id)
    data_item = FixtureDataItem.get(data_item_id)
    user = CommCareUser.get(user_id)
    assert(data_type.doc_type == FixtureDataType._doc_type)
    assert(data_type.domain == domain)
    assert(data_item.doc_type == FixtureDataItem._doc_type)
    assert(data_item.domain == domain)
    assert(data_item.data_type_id == data_type_id)
    assert(user.doc_type == CommCareUser._doc_type)
    assert(user.domain == domain)

    print request.method

    if request.method == 'POST':
        data_item.add_user(user)
        return json_response({})
    elif request.method == 'DELETE':
        data_item.remove_user(user)
        return json_response({})
    else:
        return HttpResponseBadRequest()

@require_can_edit_fixtures
def groups(request, domain):
    groups = Group.by_domain(domain)
    return json_response(map(strip_json, groups))

@require_can_edit_fixtures
def users(request, domain):
    users = CommCareUser.by_domain(domain)
    return json_response(map(prepare_user, users))

@require_can_edit_fixtures
def view(request, domain, template='fixtures/view.html'):
    return render_to_response(request, template, {})


class UploadItemLists(TemplateView):

    template_name = 'fixtures/upload_item_lists.html'

    def get_context_data(self, **kwargs):
        """TemplateView automatically calls this to render the view (on a get)"""
        return {}

    @method_decorator(get_file)
    def post(self, request):
        """View's dispatch method automatically calls this"""

        try:
            workbook = WorkbookJSONReader(request.file)
        except AttributeError:
            return HttpResponseBadRequest("Error processing your Excel (.xlsx) file")

        try:
            data_types = workbook.worksheets['types']
        except KeyError:
            return HttpResponseBadRequest("Workbook does not have a sheet called 'types'")

        for dt in data_types:
            print "DataType"
            print dt

            for di in workbook.worksheets[dt['tag']]:
                print "DataItem"
                print di

        for dt in data_types:
            data_type = FixtureDataType(
                domain=self.domain,
                name=dt['name'],
                tag=dt['tag'],
                fields=dt['field'],
            )
            data_type.save()
            data_items = workbook.worksheets[data_type.tag]
            for di in data_items:
                data_item = FixtureDataItem(
                    domain=self.domain,
                    data_type_id=data_type.get_id,
                    fields=di['field']
                )
                data_item.save()
                for group_name in di['group']:
                    group = Group.by_name(self.domain, group_name)
                    if group:
                        data_item.add_group(group)
                for raw_username in di['user']:
                    username = normalize_username(raw_username, self.domain)
                    user = CommCareUser.get_by_username(username)
                    if user:
                        data_item.add_user(user)

        return HttpResponse()

    @method_decorator(require_can_edit_fixtures)
    def dispatch(self, request, domain, *args, **kwargs):
        self.domain = domain
        return super(UploadItemLists, self).dispatch(request, *args, **kwargs)