$(function () {
        $('#user-roles-table').userRoles({
            userRoles: {{ user_roles|JSON }},
    defaultRole: {{ default_role|JSON }},
saveUrl: '{% url post_user_role domain %}',
    reportOptions: {{ report_list|JSON }},
allowEdit: {{ request.couch_user.is_domain_admin|BOOL }}
});
$('#user-roles-table').show();
});