from django import forms
from .models import ScheduledTask

class ScheduledTaskForm(forms.Form):
    script = forms.ChoiceField(label="Select Script")
    cron_schedule = forms.CharField(
        max_length=100, 
        label="Cron Schedule", 
        help_text="e.g. '* * * * *' for every minute",
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )

