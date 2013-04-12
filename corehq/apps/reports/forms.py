from django import forms
from django.core.validators import MinLengthValidator
from hqstyle.forms.fields import MultiEmailField
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit
from .models import ReportNotification


class ScheduledReportForm(forms.Form):
    config_ids = forms.MultipleChoiceField(
        label="Saved report(s)",
        validators=[MinLengthValidator(1)],
        help_text='Note: not all built-in reports support email delivery, so'
                  ' some of your saved reports may not appear in this list')

    day_of_week = forms.TypedChoiceField(
        label='Day',
        coerce=int,
        choices=(('Daily',
                        ((-1, 'Every Day'),)),
                 ('Once a week on...',
                        ReportNotification.day_choices())))

    hours = forms.TypedChoiceField(
        label='Time',
        coerce=int,
        choices=ReportNotification.hour_choices(),
        help_text='Sorry, at the moment all times are in GMT.')

    send_to_owner = forms.BooleanField(
        label='Send to me',
        required=False)

    recipient_emails = MultiEmailField(
        label='Other recipients',
        required=False)

    def __init__(self, *args, **kwargs):
        self.helper = FormHelper()
        self.helper.form_class = 'form-horizontal'
        self.helper.add_input(Submit('submit', 'Submit'))

        super(ScheduledReportForm, self).__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super(ScheduledReportForm, self).clean()
        _verify_email(cleaned_data)
        return cleaned_data


class EmailReportForm(forms.Form):
    subject = forms.CharField(required=False)
    send_to_owner = forms.BooleanField(required=False)
    recipient_emails = MultiEmailField(required=False)
    notes = forms.CharField(required=False)

    def clean(self):
        cleaned_data = super(EmailReportForm, self).clean()
        _verify_email(cleaned_data)
        return cleaned_data


def _verify_email(cleaned_data):
    if ('recipient_emails' in cleaned_data
        and not (cleaned_data['recipient_emails'] or
                     cleaned_data['send_to_owner'])):
        raise forms.ValidationError("You must specify at least one "
                                    "valid recipient")