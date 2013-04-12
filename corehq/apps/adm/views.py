from django.http import HttpResponseRedirect
from django.shortcuts import render

from corehq.apps.crud.views import BaseAdminCRUDFormView
from corehq.apps.domain.decorators import (require_superuser,
    login_and_domain_required)

@login_and_domain_required
def default_adm_report(request, domain, template="reports/base_template.html", **kwargs):
    from corehq.apps.adm.reports import ADMSectionView
    context = dict(
        domain=domain,
        project=domain,
        report=dict(
            title="Select a Report to View",
            show=True,
            slug=None,
            is_async=True,
            section_name=ADMSectionView.section_name,
        )
    )
    return render(request, template, context)

@require_superuser
def default_adm_admin(request):
    from corehq.apps.adm.admin.reports import ADMReportAdminInterface
    return HttpResponseRedirect(ADMReportAdminInterface.get_url())

class ADMAdminCRUDFormView(BaseAdminCRUDFormView):
    base_loc = "corehq.apps.adm.admin.forms"

    def is_form_class_valid(self, form_class):
        from corehq.apps.adm.admin.forms import ConfigurableADMColumnChoiceForm
        if form_class == ConfigurableADMColumnChoiceForm:
            self.template_name = "adm/forms/configurable_admin_adm_item.html"
        return True
