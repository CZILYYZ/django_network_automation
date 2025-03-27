from django import template
import re

register = template.Library()

@register.filter(name='add_class')
def add_class(value, css_class):
    """Adds a CSS class to a HTML element in string form."""
    # Simple regex to add a class to the first tag in a string
    pattern = r'(<[a-zA-Z]+)(.*?)>'
    replacement = r'\1 class="{}" \2>'.format(css_class)
    return re.sub(pattern, replacement, value, 1)

