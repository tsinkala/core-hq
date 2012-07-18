function (doc) {
    if (doc.doc_type === 'OrganizationUserRole'  || doc.doc_type === 'UserRole') {
        emit(doc.organization, null);
    }
}