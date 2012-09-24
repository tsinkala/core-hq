function (doc) {
    if (doc.doc_type === 'DomainUserRole' || doc.doc_type === 'UserRole') {
        emit(doc.domain, null);
    }
}