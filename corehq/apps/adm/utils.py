from django.conf import settings

def show_adm_nav(domain, request):
    enabled_projects = []
    if hasattr(settings, 'ADM_ENABLED_PROJECTS'):
        enabled_projects = settings.ADM_ENABLED_PROJECTS
    return request.couch_user.is_superuser or (domain in enabled_projects)


def standard_start_end_key(key, datespan=None):
    startkey_suffix = [datespan.startdate_param_utc] if datespan else []
    endkey_suffix = [datespan.enddate_param_utc] if datespan else [{}]
    return dict(
        startkey=key+startkey_suffix,
        endkey=key+endkey_suffix
    )