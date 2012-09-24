$(function () {
    function selectText(element) {
        /* copied from http://stackoverflow.com/questions/985272/jquery-selecting-text-in-an-element-akin-to-highlighting-with-your-mouse */
        var doc = document;
        var text = element[0];

        if (doc.body.createTextRange) { // ms
            var range = doc.body.createTextRange();
            range.moveToElementText(text);
            range.select();
        } else if (window.getSelection) { // moz, opera, webkit
            var selection = window.getSelection();
            var range = doc.createRange();
            range.selectNodeContents(text);
            selection.removeAllRanges();
            selection.addRange(range);
        }
    }
    $('#show_all_web_users_emails').click(function () {
        var open = false,
            p = $('#all_web_users_emails');
        p.toggle();
        open = !open;
        if (open) {
            selectText(p);
        }
        return false;
    });
});