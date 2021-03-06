{# 
references:
- https://github.com/symfony/symfony/blob/master/src/Symfony/Bridge/Twig/Resources/views/Form/form_div_layout.html.twig
- https://github.com/symfony/symfony/blob/master/src/Symfony/Bridge/Twig/Resources/views/Form/bootstrap_4_layout.html.twig
#}

{% macro form_row(row) -%}
{% set class_attr = 'form-group' %}
{%- if row.type == "checkbox" -%}
    {%- set class_attr = class_attr ~ ' form-checkbox' -%}
{%- endif -%}
<{{ row.element|default('div') }} class="{{ class_attr }}">
@if (row.type == "computed" -%}
    {# Do nothing #}
{%- elseif type== "checkbox" -%}
    {{- form_widget(row) -}}
    {{- form_label(row) -}}
@else
    {{- form_label(row) -}}
    {{- form_widget(row) -}}
{%- endif %}
    {{- form_errormessage(row) -}}
</{{ element|default('div') }}>
{%- endmacro %}


{# Labels #}

{% macro form_label(row) -%}
<label for="{{name}}">{{name}}</label>
{%- endmacro %}


{% macro form_widget(row) %}
{%- set type = type|default('text') -%}
<input type="{{ type }}" {{ widget_attributes(row) }} @if (value is not empty %}value="{{ value }}" @endif/>
{% endmacro %}

{%- macro widget_attributes(row) -%}
    {%- if not valid %}
        {% set attr = attr|merge({class: (attr.class|default('') ~ ' is-invalid')|trim}) %}
    {% endif -%}
    {{ parent() }}
{%- endmacro -%}
{# Error message #}

{% macro form_errormessage(row) -%}
{%- if error_message is not empty -%}
<div class="invalid-feedback">
    {{ error_message }}
</div>
{%- endif -%}
{%- endmacro %}