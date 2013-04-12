import datetime
from corehq.apps.domain.decorators import cls_require_previewer
from corehq.apps.domain.models import Domain
from corehq.apps.reports.dispatcher import ReportDispatcher
from corehq.apps.reports.views import datespan_default

class AppstoreDispatcher(ReportDispatcher):
    prefix = 'appstore_interface'
    map_name = 'APPSTORE_INTERFACES'

    @cls_require_previewer
    @datespan_default
    def dispatch(self, request, *args, **kwargs):
        # HACK HACK HACK HACK HACK from Tim, just moving it over
        # todo fix HACK HACK HACK HACK HACK
        dummy = Domain.get_by_name('dumdum')
        if not dummy:
            dummy = Domain(name='dumdum',
                is_active=True,
                date_created=datetime.datetime.utcnow())
            dummy.save()
        kwargs['domain'] = 'dumdum'
        return super(AppstoreDispatcher, self).dispatch(request, *args, **kwargs)
