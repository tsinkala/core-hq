from celery.task import task
from django.core.cache import cache
from soil import DownloadBase
from corehq.apps.locations.bulk import import_locations
from corehq.apps.commtrack.bulk import import_stock_reports
from soil.util import expose_download

@task
def import_locations_async(download_id, domain, file_ref_id):
    """
    Asynchronously import locations. download_id is for showing
    the results to the user through soil. file_ref_id is also a
    download_id, but should be a pointer to the import file.
    """
    download_ref = DownloadBase.get(file_ref_id)
    with open(download_ref.get_filename(), 'rb') as f:
        results_msg = '\n'.join(import_locations(domain, f))
    ref = expose_download(results_msg, 60*60*3)
    cache.set(download_id, ref)

@task
def import_stock_reports_async(download_id, domain, file_ref_id):
    """
    Same idea but for stock reports
    """
    download_ref = DownloadBase.get(file_ref_id)
    with open(download_ref.get_filename(), 'rb') as f:
        try:
            results = import_stock_reports(domain, f)
        except Exception, e:
            results = "ERROR: %s" % e
    ref = expose_download(results, 60*60*3, mimetype='text/csv')
    cache.set(download_id, ref)
