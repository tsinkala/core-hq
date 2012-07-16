function (doc) {
    if (doc.doc_type === 'OrganizationUserRole') {
        emit(doc.domain, null);
    }
}