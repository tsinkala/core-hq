from django.conf import settings
from corehq.apps.domain.models import Domain
from pillowtop.listener import ElasticPillow
from couchforms.models import XFormInstance

GR_META = {
    "settings": {
        "analysis": {
            "analyzer": {
                "lowercase_analyzer": {
                    "type": "custom",
                    "tokenizer": "keyword",
                    "filter": ["lowercase"]},
                "comma": {
                    "type": "pattern",
                    "pattern": "\s*,\s*"}}}},
    "mappings": {
        "form": {
            "properties": {}}}}

# def add_properties(base_meta, doc_type, doc_class):
#     properties = base_meta["mappings"][doc_type]["properties"]
#
#     for prop in doc_class.properties():
#         if prop in properties:
#             continue
#         properties[prop] = {"type": "string", "index": "not_analyzed"}
#
#     base_meta["mappings"][doc_type]["properties"] = properties
#     return base_meta


class GRFormPillow(ElasticPillow):
    couch_db = Domain.get_db()
    couch_filter = "report_forms/all_forms"
    es_host = settings.ELASTICSEARCH_HOST
    es_port = settings.ELASTICSEARCH_PORT
    es_index = "gr_forms"
    es_type = "form"
    es_meta = add_properties(GR_META, es_type, XFormInstance)