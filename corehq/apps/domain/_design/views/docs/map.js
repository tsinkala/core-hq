function (doc) {
    var i;
    if (doc.doc_type) {
        if (doc.domain) {
            emit([doc.domain, doc.doc_type, get_date(doc)], null);
        }
        if (doc.domains && doc.domains.length) {
            for (i = 0; i < doc.domains.length; i += 1) {
                emit([doc.domains[i], doc.doc_type, get_date(doc)], null);
            }
        }
    }

    function get_date(doc){
        // TODO: list is incomplete
        switch (doc.doc_type){
            case "CommCareCase":
            case "CommCareCase-Deleted":
                return doc.opened_on;
            case "XFormInstance":
            case "XFormInstance-Deleted":
            case "XFormError":
            case "XFormDuplicate":
            case "XFormDeprecated":
            case "XFormArchived":
            case "SubmissionErrorLog":
                return doc.received_on
            case "CommCareUser":
            case "WebUser":
                return doc.created_on;
            case "MessageLog":
            case "CallLog":
            case "SMSLog":
                return doc.date;
            case "EventLog":
                return doc.date;
            case "Application":
            case "Application-Deleted":
            case "RemoteApp":
            case "RemoteApp-Deleted":
                return doc.copy_of ? doc.built_on : null;
            default:
                return null;
        }
    }
}