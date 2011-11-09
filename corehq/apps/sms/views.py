#!/usr/bin/env python
# vim: ai ts=4 sts=4 et sw=4 encoding=utf-8
import json

import logging
from datetime import datetime
import re
from django.contrib.auth import authenticate
from django.core.urlresolvers import reverse
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseBadRequest
from corehq.apps.sms.api import send_sms
from corehq.apps.users.models import CouchUser
from corehq.apps.sms.models import MessageLog, INCOMING
from corehq.apps.groups.models import Group
from dimagi.utils.web import render_to_response
from corehq.apps.domain.decorators import login_and_domain_required
from dimagi.utils.couch.database import get_db
from django.contrib import messages

@login_and_domain_required
def messaging(request, domain, template="sms/default.html"):
    context = get_sms_autocomplete_context(request, domain)
    context['domain'] = domain
    context['messagelog'] = MessageLog.objects.filter(domain=domain).order_by('-pk')
    context['now'] = datetime.utcnow()
    return render_to_response(request, template, context)

def post(request, domain):
    """
    We assume sms sent to HQ will come in the form
    http://hqurl.com?username=%(username)s&password=%(password)s&id=%(phone_number)s&text=%(message)s
    """
    text = request.REQUEST.get('text', '')
    to = request.REQUEST.get('id', '')
    username = request.REQUEST.get('username', '')
    # ah, plaintext passwords....  
    # this seems to be the most common API that a lot of SMS gateways expose
    password = request.REQUEST.get('password', '')
    if not text or not to or not username or not password:
        error_msg = 'ERROR missing parameters. Received: %(1)s, %(2)s, %(3)s, %(4)s' % \
                     ( text, to, username, password )
        logging.error(error_msg)
        return HttpResponseBadRequest(error_msg)
    user = authenticate(username=username, password=password)
    if user is None or not user.is_active:
        return HttpResponseBadRequest("Authentication fail")
    msg = MessageLog(domain=domain,
                     # how to map phone numbers to recipients, when phone numbers are shared?
                     #couch_recipient=id, 
                     phone_number=to,
                     direction=INCOMING,
                     date = datetime.now(),
                     text = text)
    msg.save()
    return HttpResponse('OK')     


def get_sms_autocomplete_context(request, domain):
    """A helper view for sms autocomplete"""
    phone_users = CouchUser.view("users/phone_users_by_domain",
        startkey=[domain], endkey=[domain, {}], include_docs=True
    )
    groups = Group.view("groups/by_domain", key=domain, include_docs=True)

    contacts = []
    contacts.extend(['%s (group)' % group.name for group in groups])
    user_id = None
    for user in phone_users:
        if user._id == user_id:
            continue
        contacts.append(user.username)
        user_id = user._id
    return {"sms_contacts": json.dumps(contacts)}

@login_and_domain_required
def send_to_recipients(request, domain):
    recipients = request.POST.get('recipients')
    message = request.POST.get('message')
    if not recipients:
        messages.error(request, "You didn't specify any recipients")
    elif not message:
        messages.error(request, "You can't send an empty message")
    else:
        recipients = [x.strip() for x in recipients.split(',') if x.strip()]
        phone_numbers = []
        # formats: GroupName (group), "Username", +15555555555
        group_names = []
        usernames = []
        phone_numbers = []

        unknown_usernames = []
        for recipient in recipients:
            if recipient.endswith("(group)"):
                name = recipient.strip("(group)").strip()
                group_names.append(name)
            elif re.match(r'[\w\.]+', recipient):
                usernames.append(recipient)
            elif re.match(r'\+\d+', recipient):
                phone_numbers.append(recipient)


        login_ids = dict([(r['key'], r['id']) for r in get_db().view("users/by_username", keys=usernames).all()])
        for username in usernames:
            if username not in login_ids:
                unknown_usernames.append(username)
        login_ids = login_ids.values()

        users = CouchUser.view('users/by_group', keys=[[domain, gn] for gn in group_names], include_docs=True).all()
        users.extend(CouchUser.view('_all_docs', keys=login_ids, include_docs=True).all())
        phone_numbers.extend([user.default_phone_number for user in users])

        failed_numbers = []
        for number in phone_numbers:
            if not send_sms(domain, "", number, message):
                failed_numbers.append(number)
        if not failed_numbers and not unknown_usernames:
            messages.success(request, "Message sent")
        if failed_numbers:
            messages.error(request, "Couldn't send to the following number(s): +%s" % (', +'.join(failed_numbers)))
        if unknown_usernames:
            messages.error(request, "Couldn't find the following user(s): %s" % (', '.join(unknown_usernames)))
    return HttpResponseRedirect(
        request.META.get('HTTP_REFERER') or
        reverse(messaging, args=[domain])
    )