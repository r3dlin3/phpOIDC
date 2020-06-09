@extends('master')

@section('title')
@_e('TitleForgotPassword')
@endsection

@section('content')
<div class="brand">
    <img src="{!! OP_URL !!}/img/logo.png" alt="logo">
</div>
<div class="card fat">
    <div class="card-body">
        <h4 class="card-title">@_e('Forgot Password')</h4>
        <form method="POST" class="my-login-validation" action="{!! $action_url !!}" novalidate="">
            <div class="form-group">
                <label for="email">@_e('E-Mail Address')</label>
                <input id="email" type="email" class="form-control @if($error)is-invalid @endif" name="email" value="" required autofocus>
                <div class="invalid-feedback">
                    @_e('E-mail address is invalid')
                </div>
                <div class="form-text text-muted">
                    @_e('By clicking "Reset Password" we will send a password reset link')
                </div>
            </div>
            <div class="form-group m-0">
                <button type="submit" class="btn btn-primary btn-block" id="register">
                    @_e('Reset Password')
                </button>
            </div>
            <div class="mt-4 text-center">
                @_ef('Back to <a href="%s">Login</a>', $login_url)
            </div>
        </form>
    </div>
</div>
@endsection