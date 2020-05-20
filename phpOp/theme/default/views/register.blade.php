@extends('master')
{% from 'form.twig' import form_row %}

@section('title')
Login
@endsection

@section('content')
<div class="brand">
    @if (client.policy_uri is not empty %}
    <img src="{{ client.logo_uri }}" alt="{{ client.client_name }}">
    @else
    <img src="img/logo.jpg" alt="logo">
    @endif
</div>
<div class="card fat">
    <div class="card-body">
        <h4 class="card-title">{{ client.client_name }} OP Login </h4>
        @if (error %}
        <div class="alert alert-danger" role="alert">
            Authentication error
        </div>
        @endif

        <form method="POST" class="my-login-validation" action="{{ action_url }}" novalidate="">
            {% for row in form %}
            {{ form_row(row) }}
            {% endfor %}

            <div class="form-group">
                <div class="custom-checkbox custom-control">
                    <input type="checkbox" name="persist" id="persist" class="custom-control-input" tabindex="3">
                    <label for="persist" class="custom-control-label">Remember Me</label>
                </div>
            </div>

            <div class="form-group m-0">
                <button type="submit" class="btn btn-primary btn-block">
                    Register
                </button>
            </div>
            <div class="mt-4 text-center">
                Already have an account? <a href="{{ login_url }}">Login</a>
            </div>
        </form>
    </div>
    @if (client.policy_uri is not empty or client.tos_uri is not empty %}
    <div class="card-body">
        @if (client.policy_uri is not empty %}
        <a href="{{ client.policy_uri }}" class="card-link">Policy</a>
        @endif
        @if (client.tos_uri is not empty %}
        <a href="{{ client.tos_uri }}" class="card-link">Terms of use</a>
        @endif
    @endif
    </div>
    
</div>
@endsection