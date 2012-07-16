function (doc) {
    if (doc.doc_type === 'OrganizationUserRole') {
        emit(doc.organization, null);
    }
}