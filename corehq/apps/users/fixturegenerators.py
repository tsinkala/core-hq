from casexml.apps.case.xml import V1

'''
Generate user-based fixtures used in OTA restore
'''

def user_groups(user, version=V1, last_sync=None):
    """
    For a given user, return a fixture containing all the groups
    they are a part of.
    """
    if hasattr(user, "_hq_user") and user._hq_user is not None:
        return [user._hq_user.get_group_fixture()]
    return [] # this user isn't made on HQ, and this also keeps tests happy