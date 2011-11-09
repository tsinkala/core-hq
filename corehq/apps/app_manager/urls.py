from django.conf.urls.defaults import patterns, url
from django.views.generic.simple import direct_to_template

urlpatterns = patterns('corehq.apps.app_manager.views',
    (r'xform/(?P<form_unique_id>[\w-]+)/$',                                    'xform_display'),
 url(r'browse/(?P<app_id>[\w-]+)/modules-(?P<module_id>[\w-]+)/forms-(?P<form_id>[\w-]+)/source/$',
                                                                            'get_xform_source',
                                                                       name='get_xform_source'),
 url(r'browse/(?P<app_id>[\w-]+)/user_registration/source/$',                'get_user_registration_source',
                                                                       name='get_user_registration_source'),
    (r'casexml/(?P<form_unique_id>[\w-]+)/$',                                  'form_casexml'),
    (r'source/(?P<app_id>[\w-]+)/$',                                           'app_source'),
 url(r'import_app/$',                                                       'import_app', name='import_app'),
    (r'import_factory_app/$',                                               'import_factory_app'),
    (r'import_factory_module/(?P<app_id>[\w-]+)/$',                            'import_factory_module'),
    (r'import_factory_form/(?P<app_id>[\w-]+)/(?P<module_id>[\w-]+)/$',           'import_factory_form'),

 url(r'view/(?P<app_id>[\w-]+)/$',                                             'view_app', name='view_app'),
 url(r'view/(?P<app_id>[\w-]+)/modules-(?P<module_id>[\w-]+)/$',                  'view_module', name='view_module'),
 url(r'view/(?P<app_id>[\w-]+)/modules-(?P<module_id>[\w-]+)/forms-(?P<form_id>[\w-]+)/$',
                                                                            'view_form', name='view_form'),
 url(r'view/(?P<app_id>[\w-]+)/user_registration/$',                           'view_user_registration',
                                                                       name='view_user_registration'),

    (r'view/(?P<app_id>[\w-]+)/user_registration/source/$',                  'user_registration_source'),
    (r'view/(?P<app_id>[\w-]+)/modules-(?P<module_id>[\w-]+)/forms-(?P<form_id>[\w-]+)/source/$',
                                                                            'form_source'),
    (r'^$',                                                                 'default'),

    (r'new_module/(?P<app_id>[\w-]+)/$',                                       'new_module'),
 url(r'new_app/$',                                                          'new_app', name='new_app'),
    (r'new_form/(?P<app_id>[\w-]+)/(?P<module_id>[\w-]+)/$',                      'new_form'),

    (r'^delete_app/(?P<app_id>[\w-]+)/$',                                       'delete_app'),
 url(r'^delete_module/(?P<app_id>[\w-]+)/(?P<module_id>[\w-]+)/$',                 'delete_module', name="delete_module"),
 url(r'^delete_form/(?P<app_id>[\w-]+)/(?P<module_id>[\w-]+)/(?P<form_id>[\w-]+)/$', 'delete_form', name="delete_form"),

 url(r'^undo_delete_app/(?P<record_id>[\w-]+)/$',    'undo_delete_app',      name='undo_delete_app'),
 url(r'^undo_delete_module/(?P<record_id>[\w-]+)/$', 'undo_delete_module',   name='undo_delete_module'),
 url(r'^undo_delete_form/(?P<record_id>[\w-]+)/$',   'undo_delete_form',     name='undo_delete_form'),

 url(r'edit_form_attr/(?P<app_id>[\w-]+)/(?P<unique_form_id>[\w-]+)/(?P<attr>[\w-]+)/$',
                                                                            'edit_form_attr',
                                                                       name='edit_form_attr'),
    (r'rename_language/(?P<form_unique_id>[\w-]+)/$',                          'rename_language'),
    (r'edit_form_actions/(?P<app_id>[\w-]+)/(?P<module_id>[\w-]+)/(?P<form_id>[\w-]+)/$',
                                                                            'edit_form_actions'),
    # multimedia stuff
    url(r'multimedia/(?P<app_id>[\w-]+)/$',
        'multimedia_home', name='multimedia_home'),
    url(r'multimedia/(?P<app_id>[\w-]+)/download/$',
        'multimedia_list_download', name='multimedia_list_download'),

 url(r'edit_module_detail_screens/(?P<app_id>[\w-]+)/(?P<module_id>[\w-]+)/$',    'edit_module_detail_screens',
                                                                       name='edit_module_detail_screens'),
    (r'edit_module_attr/(?P<app_id>[\w-]+)/(?P<module_id>[\w-]+)/(?P<attr>[\w-]+)/$','edit_module_attr'),
    (r'delete_module_detail/(?P<app_id>[\w-]+)/(?P<module_id>[\w-]+)/$',          'delete_module_detail'),

    (r'^commcare_profile/(?P<app_id>[\w-]+)/$',                                'commcare_profile'),
 url(r'^edit_commcare_profile/(?P<app_id>[\w-]+)/$',                           'edit_commcare_profile',
                                                                       name='edit_commcare_profile'),
    (r'edit_app_lang/(?P<app_id>[\w-]+)/$',                                    'edit_app_lang'),
    (r'delete_app_lang/(?P<app_id>[\w-]+)/$',                                  'delete_app_lang'),
 url(r'edit_app_attr/(?P<app_id>[\w-]+)/(?P<attr>[\w-]+)/$',                      'edit_app_attr',
                                                                       name='edit_app_attr'),
 url(r'edit_app_translations/(?P<app_id>[\w-]+)/$',               'edit_app_translations', name='edit_app_translations'),

    (r'rearrange/(?P<app_id>[\w-]+)/(?P<key>[\w-]+)/$',                           'rearrange'),

    (r'download/(?P<app_id>[\w-]+)/$',                                         'download_index'),
    (r'download/(?P<app_id>[\w-]+)/suite.xml$',                                'download_suite'),
    (r'download/(?P<app_id>[\w-]+)/profile.xml$',                              'download_profile'),
    (r'download/(?P<app_id>[\w-]+)/profile.ccpr$',                             'download_odk_profile'),
    (r'download/(?P<app_id>[\w-]+)/(?P<lang>[\w-]+)/app_strings.txt$',            'download_app_strings'),

    (r'download/(?P<app_id>[\w-]+)/user_registration.xml$',                    'download_user_registration'),
    (r'download/(?P<app_id>[\w-]+)/modules-(?P<module_id>\d+)/forms-(?P<form_id>\d+).xml$',
                                                                            'download_xform'),
    (r'download/(?P<app_id>[\w-]+)/CommCare.jad$',                             'download_jad'),
    (r'download/(?P<app_id>[\w-]+)/CommCare_raw.jar$',                         'download_raw_jar'),
    (r'download/(?P<app_id>[\w-]+)/CommCare.jar$',                             'download_jar'),

    (r'odk/(?P<app_id>[\w-]+)/qr_code/$',                                       'odk_qr_code'),
    (r'odk/(?P<app_id>[\w-]+)/install/$',                                       'odk_install'),
    
    (r'save/(?P<app_id>[\w-]+)/$',                                             'save_copy'),
    (r'revert/(?P<app_id>[\w-]+)/$',                                           'revert_to_copy'),
    (r'delete_copy/(?P<app_id>[\w-]+)/$',                                      'delete_copy'),

    url(r'emulator/(?P<app_id>[\w-]+)/$', 'emulator', name="emulator"),
    (r'emulator/(?P<app_id>[\w-]+)/CommCare\.jar$',                            'emulator_commcare_jar'),
)   