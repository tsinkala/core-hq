function(doc) {
    if(doc.doc_type == "XFormInstance") {
        emit([doc.domain, doc.received_on], {
            time: doc.received_on,
            xmlns: doc.xmlns,
            user_id: (doc.form.meta ? doc.form.meta.userID : null),
            username: (doc.form.meta ? doc.form.meta.username : null)
        });
    }
}