function(doc){
    if(doc.doc_type == 'Application' || doc.doc_type == 'RemoteApp') {
        emit([doc.domain, doc.copy_of, doc.version], null);
        // to search accross all domains
        emit([null, doc.copy_of, doc.version], null);
    }
}