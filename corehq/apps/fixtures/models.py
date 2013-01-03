from collections import defaultdict
from xml.etree import ElementTree
from corehq.apps.users.models import CommCareUser
from couchdbkit.ext.django.schema import Document, DictProperty, StringProperty, StringListProperty
from corehq.apps.groups.models import Group
from dimagi.utils.couch.database import get_db

class FixtureTypeCheckError(Exception):
    pass

class FixtureDataType(Document):
    domain = StringProperty()
    tag = StringProperty()
    name = StringProperty()
    fields = StringListProperty()

    @classmethod
    def by_domain(cls, domain):
        return cls.view('fixtures/data_types_by_domain', key=domain, reduce=False, include_docs=True)

    @classmethod
    def by_domain_tag(cls, domain, tag):
        return cls.view('fixtures/data_types_by_domain_tag', key=[domain, tag], reduce=False, include_docs=True)

class FixtureDataItem(Document):
    domain = StringProperty()
    data_type_id = StringProperty()
    fields = DictProperty()

    @property
    def data_type(self):
        if not hasattr(self, '_data_type'):
            self._data_type = FixtureDataType.get(self.data_type_id)
        return self._data_type

    def add_owner(self, owner, owner_type):
        assert(owner.domain == self.domain)
        o = FixtureOwnership(domain=self.domain, owner_type=owner_type, owner_id=owner.get_id, data_item_id=self.get_id)
        o.save()
        return o

    def remove_owner(self, owner, owner_type):
        for ownership in FixtureOwnership.view('fixtures/ownership',
            key=['by data_item and ' + owner_type, self.domain, self.get_id, owner.get_id],
            reduce=False,
            include_docs=True
        ):
            ownership.delete()

    def add_user(self, user):
        return self.add_owner(user, 'user')

    def remove_user(self, user):
        return self.remove_owner(user, 'user')

    def add_group(self, group):
        return self.add_owner(group, 'group')

    def remove_group(self, group):
        return self.remove_owner(group, 'group')

    def type_check(self):
        fields = set(self.fields.keys())
        for field in self.data_type.fields:
            if field in fields:
                fields.remove(field)
            else:
                raise FixtureTypeCheckError("field %s not in fixture data %s" % (field, self.get_id))
        if fields:
            raise FixtureTypeCheckError("fields %s from fixture data %s not in fixture data type" % (', '.join(fields), self.get_id))

    def to_xml(self):
        xData = ElementTree.Element(self.data_type.tag)
        for field in self.data_type.fields:
            xField = ElementTree.SubElement(xData, field)
            xField.text = unicode(self.fields[field]) if self.fields.has_key(field) else ""
        return xData

    def get_groups(self, wrap=True):
        group_ids = set(
            get_db().view('fixtures/ownership',
                key=['group by data_item', self.domain, self.get_id],
                reduce=False,
                wrapper=lambda r: r['value']
            )
        )
        if wrap:
            return set(Group.view('_all_docs', keys=list(group_ids), include_docs=True))
        else:
            return group_ids

    def get_users(self, wrap=True, include_groups=False):
        user_ids = set(
            get_db().view('fixtures/ownership',
                key=['user by data_item', self.domain, self.get_id],
                reduce=False,
                wrapper=lambda r: r['value']
            )
        )
        if include_groups:
            group_ids = self.get_groups(wrap=False)
        else:
            group_ids = set()
        users_in_groups = [group.get_users(only_commcare=True) for group in Group.view('_all_docs',
            keys=list(group_ids),
            include_docs=True
        )]
        if wrap:
            return set(CommCareUser.view('_all_docs', keys=list(user_ids), include_docs=True)).union(*users_in_groups)
        else:
            return user_ids | set([user.get_id for user in users_in_groups])

    def get_all_users(self, wrap=True):
        return self.get_users(wrap=wrap, include_groups=True)

    @classmethod
    def by_user(cls, user, wrap=True, domain=None):
        group_ids = Group.by_user(user, wrap=False)


        if isinstance(user, dict):
            user_id = user.get('user_id')
            user_domain = domain
        else:
            user_id = user.user_id
            user_domain = user.domain

        fixture_ids = set(
            get_db().view('fixtures/ownership',
                keys=[['data_item by user', user_domain, user_id]] + [['data_item by group', user_domain, group_id] for group_id in group_ids],
                reduce=False,
                wrapper=lambda r: r['value'],
            )
        )
        if wrap:
            return cls.view('_all_docs', keys=list(fixture_ids), include_docs=True)
        else:
            return fixture_ids

    @classmethod
    def by_group(cls, group, wrap=True):
        fixture_ids = get_db().view('fixtures/ownership',
            key=['data_item by group', group.domain, group.get_id],
            reduce=False,
            wrapper=lambda r: r['value'],
        ).all()

        return cls.view('_all_docs', keys=list(fixture_ids), include_docs=True) if wrap else fixture_ids

    @classmethod
    def by_data_type(cls, domain, data_type):
        data_type_id = _id_from_doc(data_type)
        return cls.view('fixtures/data_items_by_domain_type', key=[domain, data_type], reduce=False, include_docs=True)

    @classmethod
    def by_data_type_and_name(cls, domain, data_type, name):
        if not name or not data_type:
            return None

        data_type_id = _id_from_doc(data_type)
        fixture_data_items = cls.by_data_type(domain, data_type_id).all()
        for fdi in fixture_data_items:
            if fdi.fields["name"].lower() == name.lower() or fdi.fields["id"].lower() == name.lower():
                return fdi
        return None

def _id_from_doc(doc_or_doc_id):
    if isinstance(doc_or_doc_id, basestring):
        doc_id = doc_or_doc_id
    else:
        doc_id = doc_or_doc_id.get_id if doc_or_doc_id else None
    return doc_id

class FixtureOwnership(Document):
    domain = StringProperty()
    data_item_id = StringProperty()
    owner_id = StringProperty()
    owner_type = StringProperty(choices=['user', 'group'])
