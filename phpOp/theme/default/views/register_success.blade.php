@extends('master')

@section('title')
@_e('TitleRegisterSuccess')
@endsection

@section('content')
<div class="brand">
    <img src="{!! $site['theme_uri'] !!}/img/logo.jpg" alt="logo">
</div>
<div class="card fat text-white bg-success">
    <div class="card-body">
        <h4 class="card-title">@_e('You are now registered.')</h4>
        <p class="card-text"> 
            @_ef('Authenticate yourself to continue.')
        </p>
        <div class="text-center">
            <a class="btn btn-primary btn-block mt-2" href="{!! $next_url !!}">@_e('Login')</a>
        </div>
    </div>
</div>
@endsection