from functools import wraps
from celery.log import get_task_logger
from celery.task import periodic_task
from datetime import datetime, timedelta
from django.core.cache import cache
from corehq.apps.receiverwrapper.models import RepeatRecord, FormRepeater
from couchdbkit.exceptions import ResourceConflict
from couchforms.models import XFormInstance
from dimagi.utils.parsing import json_format_datetime, ISO_MIN

logging = get_task_logger()

def run_only_once(fn):
    """
    If this function is running (in any thread) then don't run

    Updated with some help from:
    http://ask.github.com/celery/cookbook/tasks.html#ensuring-a-task-is-only-executed-one-at-a-time
    """
    LOCK_EXPIRE = 10*60
    fn_name = fn.__module__ + '.' + fn.__name__
    lock_id = fn_name + '_is_running'
    acquire_lock = lambda: cache.add(lock_id, "true", LOCK_EXPIRE)
    release_lock = lambda: cache.delete(lock_id)

    @wraps(fn)
    def _fn(*args, **kwargs):
        if acquire_lock():
            try:
                return fn(*args, **kwargs)
            finally:
                release_lock()
        else:
            logging.debug("%s is already running; aborting" % fn_name)
    return _fn

@periodic_task(run_every=timedelta(minutes=1))
@run_only_once
def check_repeaters():
    now = datetime.utcnow()

    repeat_records = RepeatRecord.all(due_before=now)

    for repeat_record in repeat_records:
        try:
            repeat_record.fire()
        except AttributeError:
            logging.exception("Error firing repeat record %s" % repeat_record.get_id)
            raise

        try:
            repeat_record.save()
        except ResourceConflict:
            logging.error("ResourceConflict with repeat_record %s: %s" % (repeat_record.get_id, repeat_record.to_json()))
            raise

@periodic_task(run_every=timedelta(minutes=1))
def check_inline_form_repeaters(post_fn=None):
    """old-style FormRepeater grandfathered in"""
    now = datetime.utcnow()
    forms = XFormInstance.view('receiverwrapper/forms_with_pending_repeats',
        startkey="",
        endkey=json_format_datetime(now),
        include_docs=True,
    )

    for form in forms:
        if hasattr(form, 'repeats'):
            for repeat_record in form.repeats:
                record = dict(repeat_record)
                url = record.pop('url')
                record = RepeatRecord.wrap(record)
                record.payload_id = form.get_id

                record._repeater = FormRepeater(url=url)
                record.fire(post_fn=post_fn)
                record = record.to_json()
                record['url'] = url
                repeat_record.update(record)
            form.save()