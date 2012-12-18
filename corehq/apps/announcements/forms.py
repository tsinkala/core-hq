from django import forms
from django.forms.widgets import Textarea
from hqstyle.forms import fields as hq_fields
from corehq.apps.announcements.models import HQAnnouncement
from corehq.apps.crud.models import BaseAdminCRUDForm

class HQAnnouncementForm(BaseAdminCRUDForm):
    doc_class = HQAnnouncement

    title = forms.SlugField(label="Title")
    summary = forms.CharField(label="Summary",
        widget=Textarea()
    )
    highlighted_selectors = hq_fields.CSVListField(label="Highlighted Selectors",
        help_text="A comma separated list of css selectors to highlight",
        required=False,
        widget=Textarea(attrs=dict(style="height:80px;width:340px;"))
    )
