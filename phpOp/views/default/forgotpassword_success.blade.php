@extends('master')

@section('title')
@_e('TitlePasswordResetMailSentSuccess')
@endsection

@section('content')
<div class="brand">
    <img src="{!! $site['theme_uri'] !!}/img/logo.jpg" alt="logo">
</div>
<div class="card fat text-white bg-success">
    <div class="card-body">
        <h4 class="card-title">@_e('E-mail sent.')</h4>
        <p class="card-text"> 
            @_ef('You will receive an e-mail to reset your password. Check your mails, especially in the spam folder.')
        </p>
    </div>
</div>
@endsection