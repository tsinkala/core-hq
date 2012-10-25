"""
Couch Groups for Users
Hierachical data is stored as described in: 
http://probablyprogramming.com/2008/07/04/storing-hierarchical-data-in-couchdb
"""
from __future__ import absolute_import
import re
from couchdbkit.ext.django.schema import *
from corehq.apps.users.models import CouchUser, CommCareUser
from dimagi.utils.couch.undo import UndoableDocument, DeleteDocRecord, DELETED_SUFFIX

class Group(UndoableDocument):
    """
    The main use case for these 'groups' of users is currently
    so that we can break down reports by arbitrary regions.
    
    (Things like who sees what reports are determined by permissions.) 
    """
    domain = StringProperty()
    name = StringProperty()
    # a list of user ids for users
    users = ListProperty()
    path = ListProperty()
    case_sharing = BooleanProperty()
    reporting = BooleanProperty(default=True)

    def add_user(self, couch_user_id):
        if not isinstance(couch_user_id, basestring):
            couch_user_id = couch_user_id.user_id
        if couch_user_id not in self.users:
            self.users.append(couch_user_id)
        self.save()
        
    def remove_user(self, couch_user_id):
        if not isinstance(couch_user_id, basestring):
            couch_user_id = couch_user_id.user_id
        if couch_user_id in self.users:
            for i in range(0,len(self.users)):
                if self.users[i] == couch_user_id:
                    del self.users[i]
                    self.save()
                    return
    
    def add_group(self, group):
        group.add_to_group(self)

    def add_to_group(self, group):
        """
        food = Food(path=[food_id])
        fruit = Fruit(path=[fruit_id])
        
        If fruit.add_to_group(food._id):
            then update fruit.path to be [food_id, fruit_id]
        """
        group_id = group._id
        if group_id in self.path:
            raise Exception("Group %s is already a member of %s" % (self._id, group_id))
        new_path = [group_id]
        new_path.extend(self.path)
        self.path = new_path
        self.save()
    
    def remove_group(self, group):
        group.remove_from_group(self)

    def remove_from_group(self, group):
        """
        food = Food(path=[food_id])
        fruit = Fruit(path=[food_id, fruit_id])
        
        If fruit.remove_from_group(food._id):
            then update fruit.path to be [fruit_id]
        """
        group_id = group._id
        if group_id not in self.path:
            raise Exception("Group %s is not a member of %s" % (self._id, group_id))
        index = 0
        for i in range(0,len(self.path)):
            if self.path[i] == group_id:
                index = i
                break
        self.path = self.path[index:]
        self.save()

    def get_user_ids(self, is_active=True):
        return [user.user_id for user in self.get_users(is_active)]

    def get_users(self, is_active=True, only_commcare=False):
        users = [CouchUser.get_by_user_id(user_id) for user_id in self.users]
        users = [user for user in users if not user.is_deleted()]
        if only_commcare is True:
            users = [user for user in users if user.__class__ == CommCareUser().__class__]
        if is_active is True:
            return [user for user in users if user.is_active]
        else:
            return users
    
    @classmethod
    def by_domain(cls, domain):
        key = [domain]
        return cls.view('groups/by_name', startkey=key, endkey=key + [{}], include_docs=True)

    @classmethod
    def by_name(cls, domain, name):
        return cls.view('groups/by_name', key=[domain, name], include_docs=True).one()

    @classmethod
    def by_user(cls, user, wrap=True):
        try:
            user_id = user.user_id
        except AttributeError:
            user_id = user
        results = cls.view('groups/by_user', key=user_id, include_docs=wrap)
        if wrap:
            return results
        else:
            return [r['id'] for r in results]

    @classmethod
    def get_case_sharing_groups(cls, domain, wrap=True):
        all_groups = cls.by_domain(domain)
        if wrap:
            return [group for group in all_groups if group.case_sharing]
        else:
            return [group._id for group in all_groups if group.case_sharing]


    @classmethod
    def get_reporting_groups(cls, domain):
        key = ['^Reporting', domain]
        return cls.view('groups/by_name', startkey=key, endkey=key + [{}], include_docs=True)


    def create_delete_record(self, *args, **kwargs):
        return DeleteGroupRecord(*args, **kwargs)

    @property
    def display_name(self):
        if self.name:
            return self.name
        else:
            return "[No Name]"
    
class DeleteGroupRecord(DeleteDocRecord):
    def get_doc(self):
        return Group.get(self.doc_id)