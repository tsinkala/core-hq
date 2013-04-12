var getLocalizedString = function (property, language) {
    // simple utility to localize a string based on a dict of 
    // language mappings.
    return localize(this.get(property), language);
};

var localize = function(obj, language) {
    var s = obj[language];
    if (!s) {
        for (var lang in obj) {
            if (obj.hasOwnProperty(lang) && obj[lang]) {
                s = obj[lang];
                break;
            }
        }
    }
    return s || localize.NOT_FOUND;
};
localize.NOT_FOUND = '?';

var getCloudCareUrl = function(urlRoot, appId, moduleId, formId, caseId) {
    var url = urlRoot;
    if (appId !== undefined) {
        url = url + "view/" + appId;
        if (moduleId !== undefined) {
            url = url + "/" + moduleId;
            if (formId !== undefined) {
                url = url + "/" + formId;
                if (caseId !== undefined) {
                    url = url + "/" + caseId;
                }
            }
        }  
    }
    return url;
};

var getFormUrl = function(urlRoot, appId, moduleId, formId) {
    // TODO: make this cleaner
    return urlRoot + "view/" + appId + "/modules-" + moduleId + "/forms-" + formId + "/context/";
};

var getFormEntryUrl = function (urlRoot, appId, moduleId, formId, caseId) {
    return urlRoot + getFormEntryPath(appId, moduleId, formId, caseId);
}
var getFormEntryPath = function(appId, moduleId, formId, caseId) {
    // TODO: make this cleaner
    var url = "view/" + appId + "/" + moduleId + "/" + formId;
    if (caseId) {
        url = url + '/case/' + caseId
    }
    url += "/enter/";
    return url;
};

var getSubmitUrl = function (urlRoot, appId) {
    // TODO: make this cleaner
    return urlRoot + "/" + appId + "/";
};

var getCaseFilterUrl = function(urlRoot, appId, moduleId, special) {
    // TODO: make this cleaner
    var url = urlRoot + "module/" + appId + "/modules-" + moduleId + "/";
    if (special === 'task-list') {
        url += '?task-list=true';
    }
    return url
};

var showError = function (message, location, autoHideTime) {
    if (message === undefined) {
        message = "sorry, there was an error";
    }
    _show(message, location, autoHideTime, "alert alert-error");
};

var showSuccess = function (message, location, autoHideTime) {
    if (message === undefined) {
        message = "success";
    }
    _show(message, location, autoHideTime, "alert alert-success");
};

var _show = function (message, location, autoHideTime, classes) {
    var alert = $("<div />").addClass(classes).text(message);
    alert.append($("<a />").addClass("close").attr("data-dismiss", "alert").html("&times;"));
    location.append(alert);
    if (autoHideTime) {
        alert.delay(autoHideTime).fadeOut(500);
    }
};

var showLoading = function (selector) {
    selector = selector || "#loading";
    $(selector).show();
};

var hideLoading = function (selector) {
    selector = selector || "#loading";
    $(selector).hide();
};

var hideLoadingCallback = function () {
    hideLoading();
};
