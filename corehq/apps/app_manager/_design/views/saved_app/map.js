function(doc){
    if((doc.doc_type == 'Application' || doc.doc_type == 'RemoteApp') && doc.copy_of != null) {
        emit([doc.domain, doc.copy_of, doc.version], {
            doc_type: doc.doc_type,
            short_url: doc.short_url,
            version: doc.version,
            _id: doc._id,
            name: doc.name,
            build_spec: doc.build_spec,
            copy_of: doc.copy_of,
            domain: doc.domain,
            built_on: doc.built_on,
            built_with: doc.built_with,
            build_comment: doc.build_comment
        });
    }
}