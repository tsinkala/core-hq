// copied and modified from https://gist.github.com/dsully/1938283
$(function () {

    function loadPage(url) {
        window.location.href = url;
    }

    // Handle tabs, page reloads & browser forward/back history.
    var History = window.History;

    if (!History.enabled) {
        return false;
    }

    var statechange = function () {
        var State = History.getState();
        var hash  = History.getHash();
        // Our default tab.
        if (!State.data || !State.data.tab) {
            if (hash) {
                State.data.tab = hash;
                window.location.hash = '';
            } else {
                State.data.tab = 'DEFAULT ACTIVE TAB';
            }
        }
        var link = $('a[data-toggle="tab"][href$="#' + State.data.tab + '"]');
        if (link.length === 0) {
            // if you can't find it by hash, try matching the url
            // this is for first loading a page,
            // where State.data.tab won't be available
            link = $('a[data-toggle="tab"][href^="' + window.location.pathname + '"]');
            if (link.length !== 0) {
                History.replaceState({
                    tab: link.attr('href').split('#')[1]
                }, null, State.url);
            }
        }
        link.tab('show');
    };
    $(window).bind('load', statechange);
    History.Adapter.bind(window, 'statechange', statechange);
    History.Adapter.bind(window, 'statechange', function () {
        var State = History.getState();
        if (!State.data || !State.data.tab) {
            // just go to the url specified with a reload
            loadPage(window.location.href);
        }
    });

    $('a[data-toggle="tab"]').on('show', function (event) {

        // Set the selected tab to be the current state. But don't update the URL.
        var url = event.target.href.split("#")[0];
        var tab = event.target.href.split("#")[1];

        var State = History.getState();

        if (url === window.location.href) {
            // for tabs that we don't want to change the url on
            return;
        }

        if ($('#' + tab).length === 0) {
            loadPage(url);
        }
        if (!confirm('really?')) {
            return false;
        }
        // Don't set the state if we haven't changed tabs.
        if (State.data.tab != tab) {
            History.pushState({'tab': tab}, null, url);
        }
    });
    $(window).on('beforeunload', function () {
        $('.next-to-sidebar').html('');
        setTimeout(function () {
            $('<i class="icon-spinner icon-spin icon-4x"></i>').css({
                position: 'fixed',
                top: $(window).height()/2,
                left: $(window).width()/2
            }).appendTo('body');
        }, 0);
    });
});
