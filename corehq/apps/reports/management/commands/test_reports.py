from django.core.management.base import LabelCommand
from corehq.apps.reports.tasks import daily_reports, weekly_reports

class Command(LabelCommand):
    help = "Tests sending reports. Equvalent to firing the celery tasks right NOW."
    args = ""
    label = ""
    
    def handle(self, *args, **options):
        daily_reports()
        weekly_reports()
        