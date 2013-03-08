from corehq.apps.data_interfaces.interfaces import DataInterface

class ImportCases(DataInterface):
    name = "Import Cases from Excel"
    slug = "import_cases"
    description = "Import case data from an external Excel file"
    report_template_path = "importer/import_cases.html"
    gide_filters = True
    asynchronous = False

    @classmethod
    def is_visible(cls, domain=None, couch_user=None, project=None):
        if domain == 'khayelitsha':
            return True

        return couch_user.is_superuser or couch_user.is_previewer()
